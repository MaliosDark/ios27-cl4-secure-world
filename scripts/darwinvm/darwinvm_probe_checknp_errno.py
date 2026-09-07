"""Diagnostic: make each `error = ENOMEM` site in shared_region_check_np report a
DISTINCT errno, so dyld's "check_np(): -1, errno N" pinpoints which sub-call fails.

shared_region_check_np (bsd/vm/vm_unix.c) sets error=ENOMEM(12) after three
sub-calls: vm_shared_region_start_address, vm_shared_region_update_task, and
(arm64e) vm_shared_region_auth_remap. All three surface as the same
"errno 12" to dyld. This patch rewrites the 2nd and 3rd ENOMEM immediates to 90
and 91 so a single boot tells us the failing path:
    errno 12 -> start_address    (first ENOMEM, left as-is)
    errno 90 -> update_task       (second)
    errno 91 -> auth_remap        (third, arm64e)
Values 90/91 are otherwise-unused errnos, harmless as diagnostic markers.

Anchor: the auth-remap-failed trace cstring is referenced inside check_np; walk
back to the function prologue, then collect the `movz w?, #0xC` (ENOMEM=12)
immediates in address order and retarget the 2nd/3rd.

Usage:
    python3 -m scripts.patchers.darwinvm_probe_checknp_errno <kernelcache> [--dry-run]
"""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True

ANCHOR = b"check_np(0x%llx) vm_shared_region_auth_remap() failed"
PACIBSP = 0xD503237F


def _segs(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segs = {}
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
    for (vmaddr, vmsize, fileoff, filesize) in segs.values():
        if fileoff <= foff < fileoff + filesize:
            return vmaddr + (foff - fileoff)
    return -1


def _find_cstring_start(data, needle):
    idx = data.find(needle)
    if idx < 0:
        return -1
    start = idx
    while start > 0 and data[start - 1] != 0:
        start -= 1
    return start


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


def _walk_back_prologue(data, foff, max_back=0x1200):
    for off in range(foff, max(foff - max_back, 0), -4):
        if struct.unpack_from("<I", data, off)[0] == PACIBSP:
            return off
    return -1


def _is_movz_w_imm(insn_word, imm):
    # MOVZ Wd, #imm  (32-bit): 0101 0010 100 imm16 Rd ; hw=0
    if (insn_word & 0xFFE00000) != 0x52800000:
        return False
    return ((insn_word >> 5) & 0xFFFF) == imm


def _movz_w(rd, imm):
    return 0x52800000 | ((imm & 0xFFFF) << 5) | (rd & 0x1F)


def probe(filepath, dry_run=False):
    data = bytearray(open(filepath, "rb").read())
    segs = _segs(data)
    exe = segs.get("__TEXT_EXEC")
    if not exe:
        print("[-] no __TEXT_EXEC"); return False
    ev, evs, ef, efs = exe

    s_foff = _find_cstring_start(data, ANCHOR)
    if s_foff < 0:
        print("[-] anchor not found"); return False
    s_va = _foff_to_va(segs, s_foff)
    xref = _find_adrp_add_xref(data, ev, ef, efs, s_va)
    if xref < 0:
        print("[-] no xref to check_np"); return False
    fn = _walk_back_prologue(data, xref)
    if fn < 0:
        print("[-] check_np prologue not found"); return False
    fn_va = ev + (fn - ef)
    print(f"[checknp] shared_region_check_np @ VA 0x{fn_va:X} (fileoff 0x{fn:X})")

    # Collect movz w?, #0xC (ENOMEM) between prologue and end of function.
    # Function end: first RET/RETAB after the anchor xref.
    end = xref
    for off in range(xref, min(xref + 0x400, len(data) - 4), 4):
        w = struct.unpack_from("<I", data, off)[0]
        if w in (0xD65F03C0, 0xD65F0FFF):  # RET / RETAB
            end = off + 4
            break

    sites = []
    for off in range(fn, end, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if _is_movz_w_imm(w, 0xC):
            rd = w & 0x1F
            sites.append((off, rd))

    print(f"[checknp] found {len(sites)} `movz w?, #0xC` (ENOMEM) sites:")
    for i, (off, rd) in enumerate(sites):
        print(f"    [{i}] VA 0x{ev + (off - ef):X}  w{rd}")

    if len(sites) < 2:
        print("[-] expected >=2 ENOMEM sites; aborting (manual review)")
        return False

    # Leave site[0] = 12 (start_address). Retarget the rest: 90, 91, ...
    new_errnos = [12, 90, 91, 92, 93]
    plan = []
    for i, (off, rd) in enumerate(sites):
        want = new_errnos[i] if i < len(new_errnos) else 99
        if want != 12:
            plan.append((off, rd, want))

    print("[checknp] plan (errno -> path):  12=start_address  90=update_task  91=auth_remap")
    for off, rd, want in plan:
        print(f"    patch VA 0x{ev + (off - ef):X}: movz w{rd},#0xC -> #{want}")

    if dry_run:
        print("[checknp] dry-run: no write")
        return True

    for off, rd, want in plan:
        struct.pack_into("<I", data, off, _movz_w(rd, want))
    open(filepath, "wb").write(data)
    print("[checknp] wrote distinct-errno probe")
    return True


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(f"Usage: {sys.argv[0]} <kernelcache> [--dry-run]"); sys.exit(1)
    ok = probe(args[0], dry_run="--dry-run" in sys.argv)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
