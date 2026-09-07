"""darwin-vm Image4 magazine bypass for SEP-less boot.

Patches the AppleImage4 kext's nonce/magazine system in a kernelcache
so that cryptex validation proceeds without SEP hardware. This enables
the dyld shared cache (shipped inside the Cryptex1,SystemOS) to be
mapped into the shared region, which is required for launchd to load
libSystem and continue userspace boot.

Context: darwin-vm boots XNU directly (no iBoot), so the device tree
has no /chosen/asmb manifest and no SEP to provide nonce storage. The
magazine system logs "failed to read nonce slot data: 2" for all 12
nonce domains and refuses to validate the cryptex, leaving dyld with
a "(null)" cache path.

The patches stub out the functions that perform SEP I/O for nonce slot
operations, making them return 0 (success) with no side effects. This
is the kernel-side equivalent of the vphone writeup's iBoot patch to
image4_validate_property_callback.

Usage:
    python3 -m scripts.patchers.darwinvm_patch_img4_magazine <kernelcache>

The kernelcache must be a MH_FILESET (type 12) with the
com.apple.security.AppleImage4 fileset entry.
"""

import struct
import sys

from ._asm import (
    NOP,
    RET,
    asm,
    disasm_at,
    rd32,
    wr32,
    _log_asm,
)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True

PACIBSP = 0xD503237F
RETAB   = 0xD65F0FFF
MOV_X0_0 = struct.unpack("<I", asm("mov x0, #0"))[0]


def _parse_fileset_entry(data, name):
    """Find a fileset entry by bundle ID in an MH_FILESET kernelcache.

    Returns (fileoff, vmaddr) or None.
    """
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:
        return None
    filetype = struct.unpack_from("<I", data, 12)[0]
    if filetype != 12:
        return None

    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x80000035:
            vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
            fileoff = struct.unpack_from("<Q", data, off + 16)[0]
            entry_id_off = struct.unpack_from("<I", data, off + 24)[0]
            entry_id = data[off + entry_id_off : off + cmdsize].split(b"\0")[0].decode(errors="replace")
            if entry_id == name:
                return fileoff, vmaddr
        off += cmdsize
    return None


def _parse_kext_segments(data, kext_fileoff):
    """Parse segments of a kext embedded in an MH_FILESET.

    Returns dict: segname -> (vmaddr, vmsize, fileoff, filesize)
    """
    kext = data[kext_fileoff:]
    magic = struct.unpack_from("<I", kext, 0)[0]
    if magic != 0xFEEDFACF:
        return {}

    ncmds = struct.unpack_from("<I", kext, 16)[0]
    segs = {}
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(kext):
            break
        cmd, cmdsize = struct.unpack_from("<II", kext, off)
        if cmd == 0x19:
            segname = kext[off + 8 : off + 24].split(b"\0")[0].decode()
            vmaddr = struct.unpack_from("<Q", kext, off + 24)[0]
            vmsize = struct.unpack_from("<Q", kext, off + 32)[0]
            fileoff = struct.unpack_from("<Q", kext, off + 40)[0]
            filesize = struct.unpack_from("<Q", kext, off + 48)[0]
            segs[segname] = (vmaddr, vmsize, fileoff, filesize)
        off += cmdsize
    return segs


def _find_string_in_section(data, section_fileoff, section_size, needle):
    """Find needle in a section, returning the enclosing C string's START.

    Code references the first byte of a null-terminated string, not a substring
    inside it. After matching `needle`, back-scan to the previous null byte so
    the returned file offset (and the VA derived from it) is the string start
    that ADRP+ADD actually points at. Returns -1 if not found.
    """
    region = data[section_fileoff : section_fileoff + section_size]
    idx = region.find(needle)
    if idx < 0:
        return -1
    start = idx
    while start > 0 and region[start - 1] != 0:
        start -= 1
    return section_fileoff + start


def _find_adrp_add_xref(data, exec_vmaddr, exec_fileoff, exec_filesize,
                         str_vmaddr):
    """Find ADRP+ADD pair in __TEXT_EXEC targeting str_vmaddr.

    Returns the file offset of the ADRP instruction, or -1.
    """
    target_page = str_vmaddr & ~0xFFF
    target_pageoff = str_vmaddr & 0xFFF

    code = data[exec_fileoff : exec_fileoff + exec_filesize]
    for i in range(0, len(code) - 8, 4):
        insn_a = struct.unpack_from("<I", code, i)[0]
        insn_b = struct.unpack_from("<I", code, i + 4)[0]

        if (insn_a & 0x9F000000) != 0x90000000:
            continue
        if (insn_b & 0xFFC00000) != 0x91000000:
            continue

        pc = exec_vmaddr + i
        immhi = (insn_a >> 5) & 0x7FFFF
        immlo = (insn_a >> 29) & 0x3
        imm = (immhi << 14) | (immlo << 12)
        if imm & (1 << 32):
            imm -= (1 << 33)
        page = (pc & ~0xFFF) + imm

        add_imm = (insn_b >> 10) & 0xFFF

        if page == target_page and add_imm == target_pageoff:
            return exec_fileoff + i
    return -1


RET = 0xD65F03C0


def _is_prologue_start(insn):
    """True if insn plausibly begins a function prologue.

    PACIBSP, or STP with SP base (Rn=31: callee-saved / frame save), or
    SUB sp, sp, #imm.
    """
    if insn == PACIBSP:
        return True
    # STP (signed offset / pre / post), Rn == SP (bits [9:5] == 0b11111)
    if (insn & 0x7FC00000) in (0x29000000, 0x29800000, 0x28800000) \
            and ((insn >> 5) & 0x1F) == 0x1F:
        return True
    # SUB sp, sp, #imm12  (Rd=Rn=SP)
    if (insn & 0xFF0003FF) == 0xD10003FF:
        return True
    return False


def _walk_back_to_prologue(data, xref_fileoff, max_back=4096):
    """Walk backwards from xref to the true function entry.

    PAC functions begin with PACIBSP; a naive "first STP x29,x30" stops mid-
    prologue (callee-saved pairs are saved before the frame pair). So:
      - return the first PACIBSP seen while walking back (definite PAC entry);
      - if a previous-function terminator (RET/RETAB) is hit first, the function
        is non-PAC and its entry is the first prologue-looking insn after that
        terminator.
    Returns file offset of function start, or -1.
    """
    for off in range(xref_fileoff, max(xref_fileoff - max_back, 0), -4):
        insn = struct.unpack_from("<I", data, off)[0]
        if insn == PACIBSP:
            return off
        if insn in (RET, RETAB):
            cand = off + 4
            c = struct.unpack_from("<I", data, cand)[0]
            if _is_prologue_start(c):
                return cand
            # intra-function RET (multiple epilogues); keep walking back
            continue
    return -1


def _stub_function(data, func_fileoff, name):
    """Overwrite a function to return 0, matching its PAC convention.

    PAC entry (PACIBSP): PACIBSP; MOV X0,#0; RETAB.
    Non-PAC entry:       MOV X0,#0; RET.
    Refuses to patch if the entry doesn't look like a prologue.
    """
    before = struct.unpack_from("<I", data, func_fileoff)[0]
    if not _is_prologue_start(before):
        print(f"  [!] {name}: entry 0x{before:08X} not a prologue, skipping")
        return False

    print(f"  Before ({name}):")
    _log_asm(data, func_fileoff, 5, func_fileoff)

    if before == PACIBSP:
        struct.pack_into("<I", data, func_fileoff, PACIBSP)
        struct.pack_into("<I", data, func_fileoff + 4, MOV_X0_0)
        struct.pack_into("<I", data, func_fileoff + 8, RETAB)
        conv = "PAC (RETAB)"
    else:
        struct.pack_into("<I", data, func_fileoff, MOV_X0_0)
        struct.pack_into("<I", data, func_fileoff + 4, RET)
        conv = "non-PAC (RET)"

    print(f"  After ({name}):")
    _log_asm(data, func_fileoff, 5, func_fileoff)
    print(f"  [+] Patched {name} -> return 0  [{conv}]")
    return True


def _patch_by_string(data, kext_segs, needle_str, patch_name):
    """Find a function by its error-string xref and stub it to return 0.

    Returns True if patched, False otherwise.
    """
    text_seg = kext_segs.get("__TEXT")
    exec_seg = kext_segs.get("__TEXT_EXEC")
    if not text_seg or not exec_seg:
        print(f"  [-] {patch_name}: missing __TEXT or __TEXT_EXEC segment")
        return False

    text_vmaddr, text_vmsize, text_fileoff, text_filesize = text_seg
    exec_vmaddr, exec_vmsize, exec_fileoff, exec_filesize = exec_seg

    needle = needle_str.encode("ascii")
    str_foff = _find_string_in_section(data, text_fileoff, text_filesize, needle)
    if str_foff < 0:
        print(f"  [-] {patch_name}: string not found: {needle_str!r}")
        return False

    str_va = text_vmaddr + (str_foff - text_fileoff)
    print(f"  Found string {needle_str!r} at VA 0x{str_va:X}")

    xref_foff = _find_adrp_add_xref(
        data, exec_vmaddr, exec_fileoff, exec_filesize, str_va
    )
    if xref_foff < 0:
        print(f"  [-] {patch_name}: no ADRP+ADD xref found")
        return False

    func_foff = _walk_back_to_prologue(data, xref_foff)
    if func_foff < 0:
        print(f"  [-] {patch_name}: could not find function prologue")
        return False

    xref_va = exec_vmaddr + (xref_foff - exec_fileoff)
    func_va = exec_vmaddr + (func_foff - exec_fileoff)
    print(f"  Xref at VA 0x{xref_va:X}, function at VA 0x{func_va:X} (fileoff 0x{func_foff:X})")

    return _stub_function(data, func_foff, patch_name)


def patch_img4_magazine_bypass(filepath):
    """Patch AppleImage4 magazine/nonce functions to bypass SEP.

    Targets the com.apple.security.AppleImage4 kext inside an MH_FILESET
    kernelcache. Stubs the functions that perform SEP nonce I/O so they
    return 0 (success), allowing the magazine system to initialize without
    actual SEP hardware.
    """
    data = bytearray(open(filepath, "rb").read())
    print(f"[img4-magazine] Loaded {len(data)} bytes from {filepath}")

    entry = _parse_fileset_entry(data, "com.apple.security.AppleImage4")
    if not entry:
        print("[-] com.apple.security.AppleImage4 not found in fileset")
        return False

    kext_fileoff, kext_vmaddr = entry
    print(f"[img4-magazine] AppleImage4 at fileoff 0x{kext_fileoff:X}")

    segs = _parse_kext_segments(data, kext_fileoff)
    for name, (va, vs, fo, fs) in segs.items():
        print(f"  {name}: VA 0x{va:X} size 0x{vs:X} fileoff 0x{fo:X}")

    patches = [
        ("failed to read nonce slot data", "nonce_slot_read"),
        ("failed to entangle nonce", "nonce_entangle"),
        ("failed to get nonce:", "nonce_get"),
        ("demand magazine i/o failed", "magazine_io"),
        ("failed to set supervisor nonce", "nonce_set_supervisor"),
        ("failed to roll supervisor nonce", "nonce_roll_supervisor"),
        ("failed to write slot after rolling", "nonce_write_slot"),
    ]

    applied = 0
    for needle, name in patches:
        print(f"\n--- {name} ---")
        if _patch_by_string(data, segs, needle, name):
            applied += 1

    if applied > 0:
        open(filepath, "wb").write(data)
        print(f"\n[img4-magazine] Applied {applied}/{len(patches)} patches to {filepath}")
    else:
        print(f"\n[img4-magazine] No patches applied")

    return applied > 0


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <kernelcache>")
        sys.exit(1)
    filepath = sys.argv[1]
    ok = patch_img4_magazine_bypass(filepath)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
