#!/usr/bin/env python3
# find_node_build.py -- find where the {next(x), key1(w), key2(w), value(x)} node
# is CONSTRUCTED: a base register Xb that receives, within a small window:
#   str  Wk1, [Xb, #8]        (key1, 32-bit)
#   str  Wk2, [Xb, #0x10]     (key2, 32-bit)
#   str  Xv , [Xb, #0x18]     (value, 64-bit)
# and ideally str Xh,[Xb] / str Xb,[reg] (link).  We decode with capstone detail
# so we match by (write-op, base-reg, disp, operand width), not text.

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
import cl4dis

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
BASE = cl4dis.BASE
TXT = cl4dis.TXT


def store_info(insn):
    """return (base_reg_id, disp, src_reg_name, is_word) for a str, else None."""
    if insn.mnemonic not in ("str", "stur"):
        return None
    if len(insn.operands) < 2:
        return None
    src = insn.operands[0]
    mem = insn.operands[1]
    if mem.type != ARM64_OP_MEM or src.type != ARM64_OP_REG:
        return None
    rn = insn.reg_name(src.value.reg)
    is_word = rn.startswith("w")
    return (mem.value.mem.base, mem.value.mem.disp, rn, is_word)


def scan():
    # linear disasm of whole __TEXT in chunks; collect stores keyed by base within window
    hits = []
    N = len(TXT)
    insns = list(md.disasm(TXT, BASE))
    # index by base register: for each store at +8(w), look ahead for +0x10(w) & +0x18(x) same base
    for i, ins in enumerate(insns):
        si = store_info(ins)
        if not si or si[1] != 8 or not si[3]:      # want str Wx,[base,#8]
            continue
        base = si[0]
        found10 = found18 = found0 = None
        for j in range(max(0, i - 8), min(len(insns), i + 9)):
            if j == i:
                continue
            sj = store_info(insns[j])
            if not sj or sj[0] != base:
                continue
            if sj[1] == 0x10 and sj[3]:
                found10 = insns[j]
            if sj[1] == 0x18 and not sj[3]:
                found18 = insns[j]
            if sj[1] == 0 and not sj[3]:
                found0 = insns[j]
        if found10 is not None and found18 is not None:
            f = cl4dis.func_start(ins.address)
            hits.append((f, ins, found10, found18, found0))
    return hits


if __name__ == "__main__":
    hits = scan()
    print("== node-build sites (str Wk1,[b,#8] + str Wk2,[b,#0x10] + str Xv,[b,#0x18]) ==")
    for f, i8, i10, i18, i0 in hits:
        print("\nFUNC 0x%08x  (phys 0x%x)" % (f, cl4dis.phys(f)))
        print("   key1  0x%08x  %s %s" % (i8.address, i8.mnemonic, i8.op_str))
        print("   key2  0x%08x  %s %s" % (i10.address, i10.mnemonic, i10.op_str))
        print("   value 0x%08x  %s %s" % (i18.address, i18.mnemonic, i18.op_str))
        if i0 is not None:
            print("   next  0x%08x  %s %s" % (i0.address, i0.mnemonic, i0.op_str))
