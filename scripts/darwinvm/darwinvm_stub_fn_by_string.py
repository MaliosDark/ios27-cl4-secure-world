"""Generic experiment tool: stub the function that CONTAINS a given cstring
(via an ADRP+ADD xref to it) so it returns 0 (KERN_SUCCESS), to test whether that
function's failure is what's blocking boot.

Handles PACIBSP, BTI-C, or plain prologues. Writes:
  PACIBSP -> PACIBSP; movz x0,#0; RETAB
  BTI C   -> BTI C;   movz x0,#0; RET
  else    -> movz x0,#0; RET

Usage:
    python3 -m scripts.patchers.darwinvm_stub_fn_by_string <kc> "<cstring substr>" [--dry-run]

Example (test vm_shared_region_update_task):
    ... darwinvm_stub_fn_by_string bootkc "update_task(%p) copyin failed"
"""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True

PACIBSP = 0xD503237F
BTI_C = 0xD503245F
RETAB = 0xD65F0FFF
RET = 0xD65F03C0
MOV_X0_0 = 0xD2800000


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


def _walk_back_prologue(data, foff, max_back=0x2000):
    for off in range(foff, max(foff - max_back, 0), -4):
        w = struct.unpack_from("<I", data, off)[0]
        if w in (PACIBSP, BTI_C):
            return off
        # STP x29,x30 frame prologue preceded by RET/RETAB terminator
        if w in (RET, RETAB):
            c = struct.unpack_from("<I", data, off + 4)[0]
            if c in (PACIBSP, BTI_C) or (c & 0x7FC003E0) in (0x29800000 | 0x3E0, 0x29000000 | 0x3E0):
                return off + 4
    return -1


def stub(filepath, needle, dry_run=False):
    data = bytearray(open(filepath, "rb").read())
    segs = _segs(data)
    exe = segs.get("__TEXT_EXEC")
    if not exe:
        print("[-] no __TEXT_EXEC"); return False
    ev, evs, ef, efs = exe

    s_foff = _cstr_start(data, needle.encode())
    if s_foff < 0:
        print(f"[-] string not found: {needle!r}"); return False
    s_va = _foff_to_va(segs, s_foff)
    print(f"[stubfn] string {needle!r} @ VA 0x{s_va:X}")

    xref = _find_adrp_add_xref(data, ev, ef, efs, s_va)
    if xref < 0:
        print("[-] no xref"); return False
    print(f"[stubfn] xref @ VA 0x{ev + (xref - ef):X}")

    fn = _walk_back_prologue(data, xref)
    if fn < 0:
        print("[-] prologue not found"); return False
    fn_va = ev + (fn - ef)
    first = struct.unpack_from("<I", data, fn)[0]
    print(f"[stubfn] function @ VA 0x{fn_va:X} (fileoff 0x{fn:X}) first insn 0x{first:08X}")
    for ins in _cs.disasm(bytes(data[fn:fn + 20]), fn_va):
        print(f"      0x{ins.address:X}: {ins.mnemonic:8s} {ins.op_str}")

    if dry_run:
        print("[stubfn] dry-run: would stub -> return 0")
        return True

    if first == PACIBSP:
        struct.pack_into("<I", data, fn + 4, MOV_X0_0)
        struct.pack_into("<I", data, fn + 8, RETAB)
        conv = "PAC/RETAB"
    elif first == BTI_C:
        struct.pack_into("<I", data, fn + 4, MOV_X0_0)
        struct.pack_into("<I", data, fn + 8, RET)
        conv = "BTI/RET"
    else:
        struct.pack_into("<I", data, fn, MOV_X0_0)
        struct.pack_into("<I", data, fn + 4, RET)
        conv = "plain/RET"
    open(filepath, "wb").write(data)
    print(f"[stubfn] stubbed @ 0x{fn_va:X} -> return 0 [{conv}]")
    return True


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        print(f'Usage: {sys.argv[0]} <kc> "<cstring>" [--dry-run]'); sys.exit(1)
    ok = stub(args[0], args[1], dry_run="--dry-run" in sys.argv)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
