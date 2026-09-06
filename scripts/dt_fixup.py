#!/usr/bin/env python3
import math
import struct
import argparse

SUPPORTED_DRIVERS=[b'AppleARM', b'aic', b'arm-io', b'uart-1,samsung']
# EXTRA_DRIVERS lets us un-mute additional device nodes for bring-up work.
# Semicolon separated, because compatible strings contain commas.
_extra = __import__('os').environ.get('EXTRA_DRIVERS', '')
SUPPORTED_DRIVERS += [x.strip().encode() for x in _extra.split(';') if x.strip()]
FREQUENCY = "u32:0x100000"
IBOOT_NAME="qemu-sptm"

AMCC_BANK_STRIDE = 0x100
AMCC_LOWER_LIMIT_REG = 0x10
AMCC_UPPER_LIMIT_REG = 0x20

class ADTNode:
  def __init__(self):
    self.props = {}
    self.children = []

  def __getitem__(self, key):
    for c in self.children:
      if c.props['name'] == key:
        return c
    raise ValueError(f"key {key} not present in node {self.props['name']}")

  def __contains__(self, key):
    return any(c.props['name'] == key for c in self.children)

  def remove_child(self, child_name):
    for c in self.children:
      if c.props['name'] == child_name:
        self.children.remove(c)
        return
    raise ValueError(f"child {child_name} not found in {self.props['name']}")

def round_up_to_multiple_of_4(i):
  return 4 * math.ceil(i/4)

def decode_null_terminated_string(s):
  return s.decode("utf8").split('\x00')[0]

def is_probably_a_string(s):
  if len(s) == 0:
    return False
  try:
    x=s.split(b'\x00')
    for e in x[1:]:
      if e != b'':
        return False
  except:
    return False

  try:
    d=s.decode("ascii").split('\x00')[0]
  except:
    return False

  if len(d) < 3:
    return False

  return all(i.isprintable() for i in d)

def decode_prop(name,prop):
  if name == "name" or is_probably_a_string(prop):
    return decode_null_terminated_string(prop)
  if len(prop) == 0:
    return "<NULL>"
  if len(prop) == 4:
    return f'u32:{hex(struct.unpack("<I",prop)[0])}'
  if len(prop) == 8:
    return f'u64:{hex(struct.unpack("<Q",prop)[0])}'
  return prop

def decode_node(dt,node):
  if len(dt) < 8:
    raise ValueError('dtree is too small')

  our_size = 0
  n_props, n_children = struct.unpack("<II", dt[0:8])
  dt = dt[8:]
  our_size += 8

  for _ in range(n_props):
    prop_name = decode_null_terminated_string(dt[0:32])
    prop_len = struct.unpack("<I", dt[32:36])[0]
    prop_len &= ~0x80000000
    prop_len = round_up_to_multiple_of_4(prop_len)
    prop = dt[36:36+prop_len]
    node.props[prop_name] = decode_prop(prop_name,prop)
    dt = dt[36+prop_len:]
    our_size += 36 + prop_len

  for _ in range(n_children):
    new_child = ADTNode()
    child_sz = decode_node(dt, new_child)
    node.children.append(new_child)
    our_size += child_sz
    dt = dt[child_sz:]

  return our_size

def _node_name(n):
  nm = n.props.get('name')
  if isinstance(nm, (bytes, bytearray)):
    nm = nm.decode(errors='replace').strip('\0')
  return str(nm)

# EXTRA_NODES un-mutes specific device tree paths by name, e.g.
#   EXTRA_NODES='arm-io/disp0;arm-io/dcp;arm-io/dart-disp0'
# This is what you want instead of EXTRA_DRIVERS whenever the compatible
# string is shared by unrelated devices (every DART is 'dart,t8110', so
# whitelisting that string wakes up every IOMMU in the SoC at once).
KEEP_NODES = {x.strip() for x in __import__('os').environ.get('EXTRA_NODES','').split(';') if x.strip()}

def del_compat(d, path=""):
  for c in d.children:
    child_path = f"{path}/{_node_name(c)}" if path else _node_name(c)
    del_compat(c, child_path)

  if 'compatible' in d.props:
    # Device tree compatible fields will be str or bytes (if the underlying
    # field is a stringlist, which we parse as bytes). To support either
    # single-str compatible fields, or stringlist fields, encode whatever we
    # got into a bytes, and then check whether any of our supported drivers are
    # a substring of the string or stringlist.
    compat=d.props['compatible']

    if type(compat) == str:
      compat = compat.encode('utf8')

    # a path like 'device-tree/arm-io/disp0' should match 'arm-io/disp0'
    kept = any(path == k or path.endswith('/' + k) for k in KEEP_NODES)
    if not kept and not any(x in compat for x in SUPPORTED_DRIVERS):
      del d.props['compatible']

def fixup_aic(aic):
  if 'compatible' not in aic.props:
    raise ValueError("aic doesn't have a 'compatible' field")

  compat=aic.props['compatible']
  if type(compat) == str:
    compat = compat.encode('utf8')

  if any(i in compat for i in [b'aic,2', b'aic,3']):
    aic.props['aic-iack-offset'] = "u64:0x1000"

def fixup_sptm(d):
  m = d['chosen']['memory-map']

  for i in [
    'TXM-ro', 'TXM-rx', 'TXM-bx', 'TXM-rw', 'TXM-le', 'TXM-entry', 'TXM-virt',
    'TrustCache',
    'BootKC-rx', 'BootKC-bx', 'BootKC-ro', 'BootKC-rs', 'BootKC-rw', 'BootKC-le', 'BootKC-virt', 'BootKC-entry',
    'DeviceTree',
    'SPTM-ro', 'SPTM-rm', 'SPTM-rx', 'SPTM-rw', 'SPTM-le', 'SPTM-entry', 'SPTM-virt',
    'BootArgs', 'slide',
    'CL4-rx', 'CL4-ro', 'CL4-rw', 'CL4-le', 'CL4-dummypage', 'CL4-entry', 'CL4-virt', 'CL4-dummypage',
    'RAMDisk',
  ]:
    # iBoot sets uninitialized regions to (-1, -1)
    m.props[i] = struct.pack("<QQ", 0xffffffffffffffff, 0xffffffffffffffff)

  # slide is always zero
  m.props['slide'] = struct.pack("<QQ", 0,0)

  # Skip the iommu init stuff (gfx-shared-region-base & friends)
  d['arm-io'].remove_child('sgx')

def get_platform_name(d):
  compat = d['arm-io'].props['compatible']
  if type(compat) == bytes:
    compat = compat.decode("utf8")

  return compat.split(",")[1]

def get_soc_gen(d):
  soc_gen_name = d['arm-io'].props['soc-generation']
  if type(soc_gen_name) != str:
    return 0

  if soc_gen_name[0] != 'H':
    return 0

  return int(soc_gen_name[1:])

def fixup(d, nvram_file):
  d.props['platform-name'] = get_platform_name(d)
  soc_gen = get_soc_gen(d)

  # DRAM_SIZE lets us grow guest memory past the stock 8GB. Booting a full root
  # filesystem means loading it as the ramdisk, and the image has to fit in DRAM
  # alongside the kernel blob.
  _dram = __import__('os').environ.get('DRAM_SIZE', '0x200000000')
  if soc_gen <= 14:
    d['chosen'].props['dram-base'] = "u64:0x800000000"
    d['chosen'].props['dram-size'] = f"u64:{_dram}"
  else:
    d['chosen'].props['dram-base'] = "u64:0x10000000000"
    d['chosen'].props['dram-size'] = f"u64:{_dram}"

  d['chosen'].props['firmware-version'] = IBOOT_NAME
  d['chosen'].props['system-firmware-version'] = IBOOT_NAME
  d['cpus']['cpu0'].props['state'] = "running"
  d['chosen'].props['random-seed'] = b'A' * len(d['chosen'].props['random-seed'])
  d['chosen'].props['kernel-ctrr-to-be-enabled'] = "u32:0"
  d['defaults'].props['serial-device'] = d['arm-io']['uart0'].props['AAPL,phandle']
  d['cpus']['cpu0'].props['memory-frequency'] = FREQUENCY
  d['cpus']['cpu0'].props['peripheral-frequency'] = FREQUENCY
  d['cpus']['cpu0'].props['fixed-frequency'] = FREQUENCY
  d['cpus']['cpu0'].props['clock-frequency'] = FREQUENCY
  d['cpus']['cpu0'].props['timebase-frequency'] = FREQUENCY
  d['chosen'].props['nvram-bank-count'] = "u32:1"
  d['chosen'].props['nvram-current-bank'] = "u32:1"
  d['chosen'].props['nvram-proxy-data'] = nvram_file.read()
  d['chosen'].props['nvram-total-size'] = f"u32:{len(d['chosen'].props['nvram-proxy-data'])}"
  d['chosen'].props['nvram-bank-size']  = f"u32:{len(d['chosen'].props['nvram-proxy-data'])}"

  if 'InvalidateHmac' in d['arm-io']['sep']['iop-sep-nub']:
    d['arm-io']['sep']['iop-sep-nub']['InvalidateHmac'].props['config'] = "u32:1"
    d['arm-io']['sep']['iop-sep-nub']['InvalidateHmac'].props['sio-hmac1-offset'] = "u64:0"
    d['arm-io']['sep']['iop-sep-nub']['InvalidateHmac'].props['sio-hmac1-disable-mask'] = "u64:0xffffffffffffffff"

  # iBoot assigns every DART instance a 'dart-id' before handing the tree to
  # SPTM. SPTM's own t8110 driver refuses to bootstrap without it:
  #   t8110dart.c:t8110dart_bootstrap_instance:2574: error -1 getting dart-id
  # and parks the CPU in a wfe loop before any console output exists. Number
  # them in tree order; SPTM only needs each instance to have a distinct id.
  _dart_id = [0]
  def _assign_dart_ids(n):
    compat = n.props.get('compatible')
    if isinstance(compat, str):
      compat = compat.encode('utf8')
    if compat and b'dart,' in compat:
      n.props['dart-id'] = f"u32:{_dart_id[0]}"
      _dart_id[0] += 1
    for c in n.children:
      _assign_dart_ids(c)
  _assign_dart_ids(d)

  # The DCP's IOP is marked user-power-managed: RTBuddy waits for a client to
  # request power instead of bringing it up itself. The only client is the
  # display driver, which needs an RTKit endpoint that only exists once the IOP
  # is running -- a cycle nothing breaks in this environment. Flip it to
  # power-managed so RTBuddy powers it at start. The two flags are mutually
  # exclusive ("power-managed and user-power-managed are mutually exclusive
  # device tree flags"), so the old one has to go.
  # RTBuddy fails start() with "Unable to determine target memory for firmware"
  # when a nub has no region-base/region-size. iop-ans-nub carries them;
  # iop-dcp-nub does not, because on real hardware iBoot has already dealt with
  # the DCP. Create the pair so the kernel loader has somewhere to publish the
  # carve-out it maps the DCP firmware into.
  if __import__('os').environ.get('DCP_REGION'):
    try:
      nub = d['arm-io']['dcp']['iop-dcp-nub']
      nub.props['region-base'] = "u64:0x0"
      nub.props['region-size'] = "u64:0x0"
      print("dt_fixup: iop-dcp-nub gained region-base/region-size",
            file=__import__('sys').stderr)
    except Exception as e:
      print(f"dt_fixup: could not add dcp region: {e}", file=__import__('sys').stderr)

  # iop-dcp-nub's only structural difference from iop-ans-nub is `routes`,
  # which points at the exclave mailbox. RTBuddy(ANS2) has no routes property at
  # all and comes up fine; RTBuddy(DCP) has one and its start() fails. Dropping
  # it asks whether RTBuddy falls back to talking to the ASC mailbox directly,
  # which is the path we actually emulate.
  if __import__('os').environ.get('DCP_NO_ROUTES'):
    import sys as _sys
    try:
      nub = d['arm-io']['dcp']['iop-dcp-nub']
      had = nub.props.pop('routes', None)
      # Keep no-firmware-service: without it RTBuddy reaches for a firmware
      # service that does not exist here and AppleDCP dereferences the null it
      # gets back (data abort with far=0xb1).
      if __import__('os').environ.get('DCP_DROP_NOFWSVC'):
        nub.props.pop('no-firmware-service', None)
      print(f"dt_fixup: iop-dcp-nub routes removed (was {had!r})", file=_sys.stderr)
    except Exception as e:
      print(f"dt_fixup: could not drop routes: {e}", file=_sys.stderr)

  # The product node advertises the platform's secure world:
  #   exclaves-enabled = 1, has-exclaves = 1
  # The kernel has a whole vocabulary for their absence ("Exclaves not supported
  # on this platform", "Exclaves disabled"), so telling it this machine has none
  # is a supported configuration rather than a hack. Drivers that route through
  # an exclave should then take their non-exclave path instead of waiting on a
  # secure service that will never appear.
  if __import__('os').environ.get('NO_EXCLAVES'):
    import sys as _sys
    try:
      prod = d['product']
      for k in ('exclaves-enabled', 'has-exclaves'):
        if k in prod.props:
          prod.props[k] = "u32:0"
      print("dt_fixup: product exclaves-enabled=0 has-exclaves=0", file=_sys.stderr)
    except Exception as e:
      print(f"dt_fixup: could not disable exclaves: {e}", file=_sys.stderr)

  # Make iop-dcp-nub structurally identical to iop-ans-nub, which is a plain
  # RTBuddy IOP that talks to its ASC mailbox directly (and which comes up
  # cleanly). The DCP's extra `routes` sends it through the secure proxy; strip
  # every DCP-only property and add the ANS-only ones, so RTBuddy treats it as an
  # ordinary coprocessor on the mailbox we emulate.
  if __import__('os').environ.get('DCP_NORMALIZE'):
    import sys as _sys
    try:
      nub = d['arm-io']['dcp']['iop-dcp-nub']
      for k in ('coredump-enable','coredump-rel-privacy-approved','no-firmware-service',
                'routes','user-power-managed','watchdog-enable'):
        nub.props.pop(k, None)
      nub.props['power-managed'] = "u32:1"
      nub.props['region-base'] = "u64:0x0"
      nub.props['region-size'] = "u64:0x0"
      for k in ('continuous-time','crashlog-non-fatal','no-hibernate-sleep','shutdown-sleep'):
        nub.props[k] = "<NULL>"
      print("dt_fixup: iop-dcp-nub normalized to match iop-ans-nub", file=_sys.stderr)
    except Exception as e:
      print(f"dt_fixup: normalize failed: {e}", file=_sys.stderr)

  _mode = __import__('os').environ.get('DCP_POWER_MODE')
  if _mode:
    import sys as _sys
    try:
      nub = d['arm-io']['dcp']['iop-dcp-nub']
      for k in ('user-power-managed', 'power-managed', 'dont-power-on', 'quiesced'):
        nub.props.pop(k, None)
      if _mode == 'auto':
        # RTBuddy powers the IOP itself at start.
        nub.props['power-managed'] = "u32:1"
      elif _mode == 'already-on':
        # Tell RTBuddy the IOP is already running, which is the state a real
        # iBoot leaves the DCP in before handing off to the kernel. The error
        # string "dont-power-on is not compatible with power-managed" shows the
        # two are mutually exclusive, so neither power flag may remain.
        nub.props['dont-power-on'] = "<NULL>"
      print(f"dt_fixup: iop-dcp-nub -> {_mode}", file=_sys.stderr)
    except Exception as e:
      print(f"dt_fixup: could not adjust iop-dcp-nub: {e}", file=_sys.stderr)

  d['arm-io'].remove_child('dockchannel-uart')

  # disable RTC timeout in IOKitInitializeTime
  # IOKitInitializeTime waits for the IORTC resource which never appears since
  # we don't load a driver for it. AppleARMPE::start checks for a "no-rtc" key
  # in the device tree root, and if so, sets a flag. Later,
  # AppleARMPE::platformAdjustService checks if that flag is set, and if so,
  # checks for an "rtc" node in the dtree root by calling IODTMatchNubWithKeys.
  # If it finds the rtc nub, it calls IOService::publishResource to publish a
  # fake RTC, allowing us to skip the 30 second timeout in IOKitInitializeTime.
  d.props['no-rtc'] = "<NULL>"
  rtc_node = ADTNode()
  rtc_node.props['name'] = 'rtc'
  rtc_node.props['__placeholder_val'] = "<NULL>"
  d.children.append(rtc_node)

  # This fixes panic(cpu 0 caller 0xfffffff008b8e7b8): "AMFI: No PMGR?\n" @ConfigurationSettings.cpp:388
  d['defaults'].props['vmm-present'] = "u32:1"

  amcc=d['chosen']['lock-regs']['amcc']
  amcc.props['aperture-count'] = "u32:1"
  amcc.props['aperture-size'] = "u32:0x4000"
  amcc.props['plane-count'] = "u32:1"
  amcc.props['plane-stride'] = "u32:0"
  amcc.props['plane-size'] = amcc.props['aperture-size']
  amcc.props['aperture-phys-addr'] = "u64:0x220000000"
  amcc.props['cache-status-reg-offset'] = "u32:0"
  amcc.props['cache-status-reg-mask'] = "u32:0"
  amcc.props['cache-status-reg-value'] = "u32:0"

  for (i,ctrr_v) in enumerate(['a', 'b', 'c', 'd']):
    ctrr=amcc[f'amcc-ctrr-{ctrr_v}']

    # this shifts lower/upper regs right by this many bytes
    # we assume it's zero in apple_amcc.c, so keep this zero
    ctrr.props['page-size-shift'] = "u32:0"

    ctrr.props['lower-limit-reg-offset'] = f"u32:{(AMCC_BANK_STRIDE*i)+AMCC_LOWER_LIMIT_REG}"
    ctrr.props['upper-limit-reg-offset'] = f"u32:{(AMCC_BANK_STRIDE*i)+AMCC_UPPER_LIMIT_REG}"
    ctrr.props['upper-limit-reg-mask'] = "u32:0xFFFFFFFF"
    ctrr.props['lower-limit-reg-mask'] = "u32:0xFFFFFFFF"
    ctrr.props['lock-reg-offset'] = "u32:0"
    ctrr.props['lock-reg-mask'] = "u32:0"
    ctrr.props['lock-reg-value'] = "u32:0"
    ctrr.props['enable-reg-offset'] = "u32:0"
    ctrr.props['enable-reg-mask'] = "u32:1"
    ctrr.props['enable-reg-value'] = "u32:1"
    ctrr.props['write-disable-reg-offset'] = "u32:0"
    ctrr.props['write-disable-reg-mask'] = "u32:1"
    ctrr.props['write-disable-reg-value'] = "u32:1"

  del_compat(d)
  fixup_aic(d['arm-io']['aic'])
  fixup_sptm(d)
  del d.props['secure-root-prefix']

# returns (length, value)
def parse_prop_entry(v) -> tuple[int, bytes]:
  if type(v) == bytes:
    return len(v), v.ljust(round_up_to_multiple_of_4(len(v)),b'\x00')

  if type(v) == int:
    raise TypeError("int type not specified")
  if type(v) == dict:
    raise TypeError("dicts aren't allowed as properties")
  if type(v) != str:
    raise ValueError(f"not a str ({type(v)})")

  if v.startswith("u32:"):
    return 4, struct.pack("<I",int(v[4:],0))
  elif v.startswith("u64:"):
    return 8, struct.pack("<Q",int(v[4:],0))
  elif v == "<NULL>":
    return 0, b""
  else:
    # add 1 for null terminator, return strlen (incl. null byte) but pad to multiple of 4
    strlen = len(v) + 1
    prop_len = round_up_to_multiple_of_4(strlen)
    rv1, rv2 = strlen, bytes(v,'utf8').ljust(prop_len,b'\x00')
    if rv2[-1] != 0:
      raise ValueError(f"Property {rv2} isn't NULL terminated ({rv2[-1]})")
    return rv1, rv2

def encode_node(d):
  outv = b""
  outv+=struct.pack("<II", len(d.props), len(d.children))

  for k,v in d.props.items():
    if len(k) >= 32:
      raise ValueError(f"property name {k} is too long")
    prop_name = bytes(k,'utf8').ljust(32,b'\x00')
    if prop_name[-1] != 0:
      raise ValueError(f"Property name {prop_name} isn't NULL terminated ({prop_name[-1]})")
    prop_len, prop_val = parse_prop_entry(v)

    if len(prop_val) % 4 != 0:
      raise ValueError(f"Property {k}'s value isn't a multiple of 4 bytes long ({prop_val})")

    outv += prop_name
    outv += struct.pack("<I", prop_len)
    outv += prop_val
    if len(outv) % 4 != 0:
      raise ValueError(f"Binary stream misaligned at property {k}")

  for c in d.children:
    outv += encode_node(c)
  return outv

def main():
  p = argparse.ArgumentParser(prog='dt_fixup')
  p.add_argument('dtree', type=argparse.FileType('rb', 0))
  p.add_argument('out', type=argparse.FileType('wb', 0))
  p.add_argument('-nvram', required=True, type=argparse.FileType('rb', 0))
  args = p.parse_args()

  dt_root = ADTNode()
  decode_node(args.dtree.read(),dt_root)
  fixup(dt_root, nvram_file=args.nvram)
  args.out.write(encode_node(dt_root))

if __name__=="__main__":
  main()

