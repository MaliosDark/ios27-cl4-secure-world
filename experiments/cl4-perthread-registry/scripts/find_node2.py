#!/usr/bin/env python3
# find_node2.py -- relaxed: any function that stores to BOTH [Xb,#8] and [Xb,#0x10]
# on the same base register within a small window (the two-key signature), plus
# whatever is at [Xb,#0x18] and [Xb,#0].  Report width too.
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
import cl4dis

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
insns = list(md.disasm(cl4dis.TXT, cl4dis.BASE))


def st(i):
    if i.mnemonic in ("str", "stur") and len(i.operands) == 2 \
            and i.operands[1].type == ARM64_OP_MEM and i.operands[0].type == ARM64_OP_REG:
        rn = i.reg_name(i.operands[0].value.reg)
        return (i.reg_name(i.operands[1].value.mem.base),
                i.operands[1].value.mem.disp, rn)
    return None


seen = set()
for n, i in enumerate(insns):
    s = st(i)
    if not s or s[1] != 8:
        continue
    base = s[0]
    o10 = o18 = o0 = None
    for j in range(max(0, n - 6), min(len(insns), n + 7)):
        sj = st(insns[j])
        if not sj or sj[0] != base:
            continue
        if sj[1] == 0x10:
            o10 = insns[j]
        if sj[1] == 0x18:
            o18 = insns[j]
        if sj[1] == 0:
            o0 = insns[j]
    if o10 is not None:
        f = cl4dis.func_start(i.address)
        if f in seen:
            continue
        seen.add(f)
        print("\nFUNC 0x%08x (phys 0x%x)  base=%s" % (f, cl4dis.phys(f), base))
        print("   +8   0x%08x  %s %s" % (i.address, i.mnemonic, i.op_str))
        print("   +0x10 0x%08x  %s %s" % (o10.address, o10.mnemonic, o10.op_str))
        if o18:
            print("   +0x18 0x%08x  %s %s" % (o18.address, o18.mnemonic, o18.op_str))
        if o0:
            print("   +0    0x%08x  %s %s" % (o0.address, o0.mnemonic, o0.op_str))
