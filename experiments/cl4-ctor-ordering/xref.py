#!/usr/bin/env python3
# Find BL/B/BLR-imm xrefs to a target vmaddr, and ADRP+ADD that compute an address.
import capstone, sys
TXTK = "/Users/maliosdark/darwin-vm/firmware/exclave_comp/txtk"
VMBASE = 0xc0000000
RXPHYS = 0x10006884000
data = open(TXTK, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

target = int(sys.argv[1], 0)
N = len(data)
# 1) direct branch xrefs (bl/b/b.cond)
print("== direct branches to 0x%x ==" % target)
off = 0
adrp_reg = {}
while off + 4 <= N:
    va = VMBASE + off
    try:
        insn = next(md.disasm(data[off:off+4], va, count=1))
    except StopIteration:
        off += 4; continue
    m = insn.mnemonic; ops = insn.op_str
    if m in ("bl","b") or m.startswith("b."):
        if ops.startswith("#"):
            t = int(ops[1:], 0)
            if t == target:
                print("  0x%08x (fo 0x%06x)  %-6s %s" % (va, off, m, ops))
    off += 4
# 2) adrp+add address materialization (page match)
print("== adrp(+add) materializing 0x%x ==" % target)
page = target & ~0xfff
off = 0
last_adrp = {}
while off + 4 <= N:
    va = VMBASE + off
    try:
        insn = next(md.disasm(data[off:off+4], va, count=1))
    except StopIteration:
        off += 4; continue
    m = insn.mnemonic; ops = insn.op_str
    if m == "adrp":
        parts = ops.split(", ")
        reg = parts[0]; imm = int(parts[1][1:], 0)
        last_adrp[reg] = (imm, va, off)
    elif m == "add" and "," in ops:
        p = ops.split(", ")
        if len(p) == 3 and p[2].startswith("#"):
            reg = p[0]; src = p[1]
            if src in last_adrp:
                base, bva, boff = last_adrp[src]
                addend = int(p[2][1:], 0)
                if base + addend == target:
                    print("  0x%08x adrp %s..+add => 0x%x (adrp fo 0x%06x)" % (va, src, target, boff))
    off += 4
