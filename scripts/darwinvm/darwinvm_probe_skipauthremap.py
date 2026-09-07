"""Experiment: stub vm_shared_region_auth_remap -> KERN_SUCCESS to test whether
the arm64e __AUTH remap is actually required in this QEMU/VM environment.

shared_region_check_np returns ENOMEM(12) solely from the auth_remap failure path
(confirmed: the only `movz w?,#0xC` in check_np sits right after the
"vm_shared_region_auth_remap() failed" trace). So auth_remap is failing and
killing launchd. This stubs auth_remap to return KERN_SUCCESS(0) without doing
the remap.

If QEMU does not truly enforce PAC on the cache __AUTH pages, launchd proceeds
(the remap was unnecessary). If PAC IS enforced, launchd will fault on
unauthenticated pointers (a NEW, different panic) -- which tells us the remap
must be made to actually work. Either outcome is decisive.

Anchor: the auth-remap-failed cstring is referenced inside check_np; the `bl`
immediately before that trace's `cbz` (the auth_remap call) gives the function.

Usage:
    python3 -m scripts.patchers.darwinvm_probe_skipauthremap <kernelcache> [--dry-run]
"""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True

ANCHOR = b"check_np(0x%llx) vm_shared_region_auth_remap() failed"
PACIBSP = 0xD503237F
RETAB = 0xD65F0FFF
RET = 0xD65F03C0
MOV_X0_0 = 0xD2800000  # movz x0, #0


def _segs(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off, segs = 32, {}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off + 8:off + 24].split(b"\0")[0].decode(errors="replace")
            segs[name] = (
                struct.unpack_from("<Q", data, off + 24)[0],
                struct.unpack_from("<Q", data, off + 32)[0],
                struct.unpack_from("<Q", data, off + 40)[0],
                struct.unpack_from("<Q", data, off + 48)[0],
            )
        off += cmdsize
    return segs


def _foff_to_va(segs, foff):
    for (v, vs, f, fs) in segs.values():
        if f <= foff < f + fs:
            return v + (foff - f)
    return -1


def _va_to_foff(segs, va):
    for (v, vs, f, fs) in segs.values():
        if v <= va < v + vs and (va - v) < fs:
            return f + (va - v)
    return -1


def _cstr_start(data, needle):
    idx = data.find(needle)
    if idx < 0:
        return -1
    while idx > 0 and data[idx - 1] != 0:
        idx -= 1
    return idx


def _find_adrp_add_xref(data, ev, ef, efs, str_va):
    tp, to = str_va & ~0xFFF, str_va & 0xFFF
    code = data[ef:ef + efs]
    for i in range(0, len(code) - 8, 4):
        a = struct.unpack_from("<I", code, i)[0]
        b = struct.unpack_from("<I", code, i + 4)[0]
        if (a & 0x9F000000) != 0x90000000 or (b & 0xFFC00000) != 0x91000000:
            continue
        pc = ev + i
        immhi = (a >> 5) & 0x7FFFF
        immlo = (a >> 29) & 0x3
        imm = (immhi << 14) | (immlo << 12)
        if imm & (1 << 32):
            imm -= (1 << 33)
        if ((pc & ~0xFFF) + imm) == tp and ((b >> 10) & 0xFFF) == to:
            return ef + i
    return -1


def _bl_target(insn_word, pc):
    if (insn_word & 0xFC000000) != 0x94000000:
        return -1
    imm = insn_word & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= (1 << 26)
    return pc + imm * 4


def probe(filepath, dry_run=False):
    data = bytearray(open(filepath, "rb").read())
    segs = _segs(data)
    exe = segs.get("__TEXT_EXEC")
    if not exe:
        print("[-] no __TEXT_EXEC"); return False
    ev, evs, ef, efs = exe

    s_foff = _cstr_start(data, ANCHOR)
    if s_foff < 0:
        print("[-] anchor not found"); return False
    s_va = _foff_to_va(segs, s_foff)
    xref = _find_adrp_add_xref(data, ev, ef, efs, s_va)
    if xref < 0:
        print("[-] no xref to check_np"); return False
    xref_va = ev + (xref - ef)
    print(f"[skipauth] auth_remap-failed trace xref @ VA 0x{xref_va:X}")

    # Walk backwards for `bl auth_remap; mov x8, x0` (result captured into x8 for
    # the `cbz w8, success`). `mov x8, x0` == ORR X8,XZR,X0 == 0xAA0003E8.
    MOV_X8_X0 = 0xAA0003E8
    bl_target = -1
    for off in range(xref - 4, max(xref - 0x100, ef), -4):
        w = struct.unpack_from("<I", data, off)[0]
        t = _bl_target(w, ev + (off - ef))
        if t != -1 and off + 4 < len(data) and \
                struct.unpack_from("<I", data, off + 4)[0] == MOV_X8_X0:
            bl_target = t
            bl_va = ev + (off - ef)
            break
    if bl_target < 0:
        print("[-] no `bl; mov x8,x0` (auth_remap call) found before the trace"); return False
    print(f"[skipauth] bl auth_remap @ VA 0x{bl_va:X} -> target 0x{bl_target:X}")

    fn_foff = _va_to_foff(segs, bl_target)
    if fn_foff < 0:
        print("[-] auth_remap target not in file"); return False
    first = struct.unpack_from("<I", data, fn_foff)[0]
    print(f"[skipauth] auth_remap @ VA 0x{bl_target:X} (fileoff 0x{fn_foff:X}) first insn 0x{first:08X}")

    # Disasm a few insns for confirmation
    for ins in _cs.disasm(bytes(data[fn_foff:fn_foff + 20]), bl_target):
        print(f"      0x{ins.address:X}: {ins.mnemonic:8s} {ins.op_str}")

    if dry_run:
        print("[skipauth] dry-run: would stub -> return 0 (KERN_SUCCESS)")
        return True

    BTI_C = 0xD503245F
    if first == PACIBSP:
        struct.pack_into("<I", data, fn_foff, PACIBSP)
        struct.pack_into("<I", data, fn_foff + 4, MOV_X0_0)
        struct.pack_into("<I", data, fn_foff + 8, RETAB)
        conv = "PAC/RETAB"
    elif first == BTI_C:
        # keep the BTI landing pad, return right after it
        struct.pack_into("<I", data, fn_foff + 4, MOV_X0_0)
        struct.pack_into("<I", data, fn_foff + 8, RET)
        conv = "BTI/RET"
    else:
        struct.pack_into("<I", data, fn_foff, MOV_X0_0)
        struct.pack_into("<I", data, fn_foff + 4, RET)
        conv = "plain/RET"
    open(filepath, "wb").write(data)
    print(f"[skipauth] stubbed vm_shared_region_auth_remap -> return 0 [{conv}]")
    return True


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(f"Usage: {sys.argv[0]} <kernelcache> [--dry-run]"); sys.exit(1)
    ok = probe(args[0], dry_run="--dry-run" in sys.argv)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
