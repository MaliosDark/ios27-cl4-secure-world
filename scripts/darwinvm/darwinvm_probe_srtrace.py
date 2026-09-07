"""Diagnostic: raise the kernel's shared_region_trace_level so the shared-region
subsystem prints WHY shared_region_check_np / the cache map fails.

This iOS 27 kernelcache ships the SHARED_REGION_TRACE strings compiled in
(e.g. "vm: shared_region: ... check_np(0x%llx) vm_shared_region_auth_remap()
failed", "update_task(%p) copyin failed", "region_slide(...) failed",
"enter: lookup failed", "map(): vm_shared_region_map_file() failed"), but they
are gated on the global `shared_region_trace_level` (0=NONE .. 3=DEBUG). At the
release default the failing trace stays silent. Setting it to 3 makes the exact
failing sub-operation print, pinpointing the "check_np(): -1, errno 12" cause
without guessing.

Not a security change: it only turns on kernel diagnostic logging.

Anchor: the check_np auth-remap-failed cstring is referenced from inside
shared_region_check_np. Just before the string load, the trace macro loads the
global via ADRP+LDR and compares it. We resolve that global and overwrite its
initialized __DATA value with 3.

Usage:
    python3 -m scripts.patchers.darwinvm_probe_srtrace <kernelcache> [--dry-run]
"""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True

ANCHOR = b"check_np(0x%llx) vm_shared_region_auth_remap() failed"


def _segs(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segs = {}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off + 8:off + 24].split(b"\0")[0].decode(errors="replace")
            vmaddr = struct.unpack_from("<Q", data, off + 24)[0]
            vmsize = struct.unpack_from("<Q", data, off + 32)[0]
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            filesize = struct.unpack_from("<Q", data, off + 48)[0]
            segs[name] = (vmaddr, vmsize, fileoff, filesize)
        off += cmdsize
    return segs


def _va_to_foff(segs, va):
    for (vmaddr, vmsize, fileoff, filesize) in segs.values():
        if vmaddr <= va < vmaddr + vmsize and (va - vmaddr) < filesize:
            return fileoff + (va - vmaddr)
    return -1


def _foff_to_va(segs, foff):
    for (vmaddr, vmsize, fileoff, filesize) in segs.values():
        if fileoff <= foff < fileoff + filesize:
            return vmaddr + (foff - fileoff)
    return -1


def _find_cstring_start(data, segs, needle):
    # Search the whole file (the string lives in the kernel fileset entry, not
    # necessarily the top-level __TEXT), then map its start offset to a VA via
    # whichever LC_SEGMENT_64 contains it.
    idx = data.find(needle)
    if idx < 0:
        return -1, -1
    start = idx
    while start > 0 and data[start - 1] != 0:
        start -= 1
    return start, _foff_to_va(segs, start)


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


def probe(filepath, dry_run=False):
    data = bytearray(open(filepath, "rb").read())
    segs = _segs(data)
    text = segs.get("__TEXT") or segs.get("__PRELINK_TEXT")
    exe = segs.get("__TEXT_EXEC")
    if not text or not exe:
        print("[-] missing segments"); return False
    ev, evs, ef, efs = exe

    s_foff, s_va = _find_cstring_start(data, segs, ANCHOR)
    if s_foff < 0 or s_va < 0:
        print(f"[-] anchor string not found (foff={s_foff:#x} va={s_va:#x})"); return False
    print(f"[srtrace] anchor '{ANCHOR.decode()[:32]}...' at VA 0x{s_va:X}")

    xref = _find_adrp_add_xref(data, ev, ef, efs, s_va)
    if xref < 0:
        print("[-] no xref to anchor (check_np)"); return False
    xref_va = ev + (xref - ef)
    print(f"[srtrace] xref inside shared_region_check_np at VA 0x{xref_va:X}")

    # Walk backwards for the trace-level gate: adrp x?, P ; ldr w?, [x?, #O] ; cmp w?, #imm
    # The ADRP+LDR resolves the global shared_region_trace_level.
    global_va = -1
    win = data[max(xref - 0x200, ef):xref]
    base = ev + (max(xref - 0x200, ef) - ef)
    insns = list(_cs.disasm(bytes(win), base))
    adrp_reg = {}
    for ins in insns:
        if ins.mnemonic == "adrp" and ins.operands:
            adrp_reg[ins.operands[0].reg] = ins.operands[1].imm
        elif ins.mnemonic == "ldr" and len(ins.operands) == 2:
            src = ins.operands[1]
            # ldr w?, [xN, #imm]
            if src.type == 3 and src.mem.base in adrp_reg and src.mem.disp >= 0:  # ARM64_OP_MEM
                cand = adrp_reg[src.mem.base] + src.mem.disp
                cf = _va_to_foff(segs, cand)
                if cf >= 0 and cf + 4 <= len(data):
                    cur = struct.unpack_from("<I", data, cf)[0]
                    # trace level is a small int (0..3)
                    if cur <= 8:
                        global_va = cand
                        global_foff = cf
                        global_cur = cur

    if global_va < 0:
        print("[-] could not resolve shared_region_trace_level global near the gate")
        print("    disasm [xref-0x120 .. xref+0x8] for manual read:")
        dstart = xref - 0x120
        for ins in _cs.disasm(bytes(data[dstart:xref + 8]), ev + (dstart - ef)):
            mark = ">>>" if ins.address == xref_va else "   "
            print(f"    {mark} 0x{ins.address:X}: {ins.mnemonic:8s} {ins.op_str}")
        return False

    print(f"[srtrace] shared_region_trace_level @ VA 0x{global_va:X} "
          f"(fileoff 0x{global_foff:X}) current value = {global_cur}")
    if dry_run:
        print("[srtrace] dry-run: would set to 3 (DEBUG)")
        return True
    struct.pack_into("<I", data, global_foff, 3)
    open(filepath, "wb").write(data)
    print("[srtrace] set shared_region_trace_level = 3 (DEBUG); wrote file")
    return True


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(f"Usage: {sys.argv[0]} <kernelcache> [--dry-run]"); sys.exit(1)
    ok = probe(args[0], dry_run="--dry-run" in sys.argv)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
