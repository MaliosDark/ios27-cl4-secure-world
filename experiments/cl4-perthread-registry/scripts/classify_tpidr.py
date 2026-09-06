#!/usr/bin/env python3
# classify_tpidr.py -- for every function that reads tpidr_el0, show whether it
# READS or WRITES the registry list, and dump the instructions touching the
# tpidr-derived pointer and offsets +0x10 / +0 / +8 / +0x18.

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
import cl4dis

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True


def body(fstart, span=0x400):
    code = cl4dis.read_vm(fstart, span)
    out = []
    for i in md.disasm(code, fstart):
        out.append(i)
        if i.mnemonic in ("ret", "retab", "retaa"):
            break
    return out


def analyze(fstart):
    ins = body(fstart)
    # taint: regs that hold tpidr-derived pointer
    tainted = set()
    lines = []
    has_write = False
    for i in ins:
        m, o = i.mnemonic, i.op_str
        note = ""
        if m == "mrs" and "tpidr_el0" in o:
            rd = i.operands[0].value.reg
            tainted = {rd}
            note = "  <- TPIDR"
        elif m == "ldr" and len(i.operands) == 2 and i.operands[1].type == ARM64_OP_MEM:
            b = i.operands[1].value.mem.base
            d = i.operands[1].value.mem.disp
            if b in tainted:
                rd = i.operands[0].value.reg
                tainted.add(rd)
                note = "  <- [tpidr+0x%x] (reg ptr propagate)" % d
        elif m in ("str", "stur") and len(i.operands) >= 2 and i.operands[1].type == ARM64_OP_MEM:
            b = i.operands[1].value.mem.base
            d = i.operands[1].value.mem.disp
            if b in tainted:
                has_write = True
                note = "  *** WRITE [tpidr-ptr+0x%x] ***" % d
        if note:
            lines.append("    0x%08x  %-6s %s%s" % (i.address, m, o, note))
    return has_write, lines


if __name__ == "__main__":
    seen = set()
    for vm, w in cl4dis.iter_text():
        if (w & 0xffffffe0) == 0xd53bd040:
            f = cl4dis.func_start(vm)
            seen.add(f)
    writers = []
    for f in sorted(seen):
        hw, lines = analyze(f)
        if hw:
            writers.append((f, lines))
    print("== functions that WRITE through a tpidr-derived pointer (%d) ==" % len(writers))
    for f, lines in writers:
        print("\nFUNC 0x%08x  (phys 0x%x)" % (f, cl4dis.phys(f)))
        for l in lines:
            print(l)
