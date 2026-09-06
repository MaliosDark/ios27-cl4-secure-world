#!/usr/bin/env python3
"""Fix RTBuddy::start()'s unconditional secure-proxy notify call -- correctly.

Supersedes patch_rtbuddy_secureproxy.py (Part 32), which had a real design
flaw: it replaced the unconditional `bl` with `cbz x0, +4`. Since a CBZ that
does not branch simply falls through to the next instruction -- which is
exactly where the branch target also lands -- that patch skipped the call in
*every* case, not just when the route is null. It was safe (no more crash) but
silently dropped a legitimate notification whenever a real secure-route object
does exist, which likely blocked forward progress in that case instead of
fixing anything.

The correct fix preserves the original call when the field is non-null and
only skips it when null. That needs more than 4 bytes at the call site, so it
redirects the `bl` to a small trampoline placed in a genuinely dead `udf #0`
padding region between two kernel functions (confirmed by disassembly: a
`retab` followed by `nop` padding followed by this run of `udf #0` bytes --
Apple's own dead-code filler, never reached in normal operation):

    trampoline:
        cbz x0, .Lret     ; unchanged behaviour when there is no secure route
        b   <original fn> ; tail-call: preserves the real notification when
                          ; there is one, and its own ret/retab returns
                          ; straight to our caller since we used `b`, not `bl`
    .Lret:
        ret

Both the trampoline and the patch-site instruction are Keystone-assembled and
verified by disassembling them back before writing, per project rules --
nothing here is a hardcoded instruction byte string.
"""
import struct, sys, argparse
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

LC_SEGMENT_64    = 0x19
LC_FILESET_ENTRY = 0x80000035

def macho_cmds(d, off):
    ncmds = struct.unpack('<I', d[off+16:off+20])[0]
    p = off + 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack('<II', d[p:p+8])
        yield p, cmd, cs
        p += cs

def fileset_fileoff(d, name):
    for p, cmd, cs in macho_cmds(d, 0):
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff = struct.unpack('<QQ', d[p+8:p+24])
            nm = d[p+32:d.find(b'\0', p+32)]
            if nm == name:
                return fileoff
    return None

def text_exec(d, fo):
    for p, cmd, cs in macho_cmds(d, fo):
        if cmd == LC_SEGMENT_64:
            segname = d[p+8:p+24].rstrip(b'\0')
            vmaddr, vmsize, foff, fsz = struct.unpack('<QQQQ', d[p+24:p+56])
            if segname == b'__TEXT_EXEC':
                return vmaddr, foff
    return None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bootkc')
    ap.add_argument('-n', '--dry-run', action='store_true')
    args = ap.parse_args()

    d = bytearray(open(args.bootkc, 'rb').read())

    rtb_fo = fileset_fileoff(d, b'com.apple.driver.RTBuddy')
    if rtb_fo is None:
        sys.exit("RTBuddy fileset not found")
    rtb_tx_va, rtb_tx_fo = text_exec(d, rtb_fo)
    if rtb_tx_va is None:
        sys.exit("RTBuddy __TEXT_EXEC not found")

    kern_fo = fileset_fileoff(d, b'com.apple.kernel')
    if kern_fo is None:
        sys.exit("com.apple.kernel fileset not found")
    kern_tx_va, kern_tx_fo = text_exec(d, kern_fo)
    if kern_tx_va is None:
        sys.exit("com.apple.kernel __TEXT_EXEC not found")

    def rtb_at(va):
        return rtb_tx_fo + (va - rtb_tx_va)

    def kern_at(va):
        return kern_tx_fo + (va - kern_tx_va)

    LDR_VA   = 0xFFFFFFF00A7BB5A4   # ldr x0, [x19, #0x21a8]  (this->secureRoute)
    PATCH_VA = 0xFFFFFFF00A7BB5A8   # bl  0xfffffff00a7cc8ac  (the unguarded call)
    REAL_FN  = 0xFFFFFFF00A7CC8AC
    TRAMP_VA = 0xFFFFFFF00AA61F00   # confirmed dead udf-#0 filler, 65+ bytes free
    RET_VA   = TRAMP_VA + 8

    ldr_fo = rtb_at(LDR_VA)
    if d[ldr_fo:ldr_fo+4] != bytes([0x60, 0xd6, 0x50, 0xf9]):
        sys.exit("anchor mismatch: expected 'ldr x0, [x19, #0x21a8]' at LDR_VA")

    patch_fo = rtb_at(PATCH_VA)
    cur = bytes(d[patch_fo:patch_fo+4])
    if (cur[3] & 0xfc) != 0x94:
        sys.exit(f"anchor mismatch: expected 'bl ...' at PATCH_VA, got {cur.hex()}")

    tramp_fo = kern_at(TRAMP_VA)
    tramp_region = bytes(d[tramp_fo:tramp_fo+16])
    if tramp_region != b'\x00' * 16:
        sys.exit(f"anchor mismatch: expected 16 zero bytes (udf filler) at "
                 f"TRAMP_VA, got {tramp_region.hex()} -- refusing to overwrite "
                 f"non-dead code")

    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    i1, _ = ks.asm(f"cbz x0, 0x{RET_VA:x}", TRAMP_VA)
    i2, _ = ks.asm(f"b 0x{REAL_FN:x}", TRAMP_VA + 4)
    i3, _ = ks.asm("ret", RET_VA)
    trampoline = bytes(i1) + bytes(i2) + bytes(i3)

    site, _ = ks.asm(f"bl 0x{TRAMP_VA:x}", PATCH_VA)
    site = bytes(site)

    # Verify both blobs disassemble back to exactly the intended instructions
    # before writing anything.
    got = list(md.disasm(trampoline, TRAMP_VA))
    want = [("cbz", f"x0, #0x{RET_VA:x}"), ("b", f"#0x{REAL_FN:x}"), ("ret", "")]
    for insn, (wm, wo) in zip(got, want):
        if insn.mnemonic != wm or (wo and insn.op_str != wo):
            sys.exit(f"trampoline verification failed: got {insn.mnemonic} "
                     f"{insn.op_str}, want {wm} {wo}")
    got_site = list(md.disasm(site, PATCH_VA))
    if not got_site or got_site[0].mnemonic != "bl" or \
       got_site[0].op_str != f"#0x{TRAMP_VA:x}":
        sys.exit("patch-site verification failed")

    print(f"RTBuddy secure-proxy notify guard v2 (trampoline):")
    print(f"  patch site 0x{patch_fo:X}: {cur.hex()} -> {site.hex()}  "
          f"(bl 0x{TRAMP_VA:x})")
    print(f"  trampoline 0x{tramp_fo:X}: {trampoline.hex()}")
    print(f"    cbz x0, +8 ; b 0x{REAL_FN:x} ; ret")

    if not args.dry_run:
        d[tramp_fo:tramp_fo+len(trampoline)] = trampoline
        d[patch_fo:patch_fo+4] = site
        open(args.bootkc, 'wb').write(d)
        print("patched")
    else:
        print("dry run, not written")

if __name__ == '__main__':
    main()
