#!/usr/bin/env python3
# cl4dis.py -- disassembly + xref helper library for CL4 (exclave secure kernel).
#
#   source /Users/maliosdark/vphone-cli/.venv/bin/activate
#   python3 cl4dis.py <cmd> [args]
#
# CL4 image maps:
#   __TEXT  -> firmware/exclave_comp/txtk (vmaddr base 0xc0000000)
#   __DATA  -> firmware/exclave_comp/tadk (vmaddr base 0xc068c000, file 0..0x48000)
# Everything derived from capstone decode / raw-encoding scans, no hardcoded dumps.

import struct, os, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

FW = "/Users/maliosdark/darwin-vm/firmware/exclave_comp"
TXT = open(os.path.join(FW, "txtk"), "rb").read()
TAD = open(os.path.join(FW, "tadk"), "rb").read()
BASE = 0xc0000000
DATA_VM = 0xc068c000
DATA_FILE_END = DATA_VM + len(TAD)     # end of file-backed __DATA (rest is bss=0)
RX_PHYS = 0x10006884000                # CL4 __TEXT physical load base (RESUME U5)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True


def phys(vm):
    return RX_PHYS + (vm - BASE)


def vm_of(ph):
    return BASE + (ph - RX_PHYS)


def read_vm(vm, n):
    if vm >= DATA_VM:
        o = vm - DATA_VM
        if o >= len(TAD):
            return b"\x00" * n          # bss
        return (TAD[o:o + n] + b"\x00" * n)[:n]
    o = vm - BASE
    return TXT[o:o + n]


def word(vm):
    return struct.unpack_from("<I", read_vm(vm, 4), 0)[0]


def dis(vm, n=40, stop=True, label=""):
    if label:
        print("== %s ==" % label)
    for i in md.disasm(read_vm(vm, n * 4), vm):
        print("  0x%08x  %08x  %-8s %s"
              % (i.address, word(i.address), i.mnemonic, i.op_str))
        if stop and i.mnemonic in ("ret", "retab", "retaa", "br", "braa", "brab"):
            break


# ---- xref scanners over __TEXT (all instructions are 4-byte aligned) ----

def iter_text():
    for off in range(0, len(TXT) - 3, 4):
        yield BASE + off, struct.unpack_from("<I", TXT, off)[0]


def find_bl(target):
    """all BL sites that call `target` (imm26 signed *4)."""
    out = []
    for vm, w in iter_text():
        if (w & 0xfc000000) == 0x94000000:            # BL
            imm = w & 0x03ffffff
            if imm & 0x02000000:
                imm -= 0x04000000
            if vm + imm * 4 == target:
                out.append(vm)
    return out


def find_adrp_to(page):
    """ADRP whose computed page == `page` (approx xref to a __DATA global)."""
    out = []
    for vm, w in iter_text():
        if (w & 0x9f000000) == 0x90000000:            # ADRP
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7ffff
            imm = ((immhi << 2) | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            base = (vm & ~0xfff) + (imm << 12)
            if base == (page & ~0xfff):
                out.append((vm, w >> 0 & 0x1f))       # (site, Rd)
    return out


def scan_msr_tpidr():
    out = []
    for vm, w in iter_text():
        if (w & 0xffffffe0) == 0x51bd040 | 0xd0000000:  # d51bd040|Rt
            pass
    # explicit correct mask:
    for vm, w in iter_text():
        if (w & 0xffffffe0) == 0xd51bd040:
            out.append((vm, w & 0x1f))
    return out


def func_start(vm):
    """walk backwards to a likely function prologue (stp x29.. / pacibsp / sub sp)."""
    a = vm & ~3
    for _ in range(400):
        w = word(a)
        # pacibsp = 0xd503237f ; paciasp=0xd503233f
        if w in (0xd503237f, 0xd503233f):
            return a
        # stp x29,x30,[sp,#-N]!  -> 0xa9b_7bfd family (pre-index, Rt=29,Rt2=30)
        if (w & 0xffe07fff) == 0xa9807bfd:
            return a
        a -= 4
    return vm & ~3


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "dis":
        vm = int(sys.argv[2], 16)
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 40
        st = not (len(sys.argv) > 4 and sys.argv[4] == "nostop")
        dis(vm, n, stop=st)
    elif cmd == "bl":
        tgt = int(sys.argv[2], 16)
        for a in find_bl(tgt):
            print("  BL 0x%x from 0x%08x  (func~0x%08x)" % (tgt, a, func_start(a)))
    elif cmd == "adrp":
        pg = int(sys.argv[2], 16)
        for a, rd in find_adrp_to(pg):
            print("  ADRP x%d, 0x%x from 0x%08x" % (rd, pg, a))
    elif cmd == "msr":
        for a, rt in scan_msr_tpidr():
            print("  msr tpidr_el0, x%d @ 0x%08x  (func~0x%08x)" % (rt, a, func_start(a)))
    else:
        print("cmds: dis <vm> [n] [nostop] | bl <target> | adrp <page> | msr")
