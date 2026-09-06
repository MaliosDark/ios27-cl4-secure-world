#!/usr/bin/env python3
# Heuristic scan for an AArch64 EL1 exception vector table in CL4 __TEXT.
# A vector table is 0x800-aligned; 16 entries at +0x80 spacing. Each used entry
# begins with valid handler code (commonly the SAME prologue: an msr SPSel/DAIF,
# or a store pair, or an unconditional branch to a common handler). We flag a
# 0x800-aligned VA where the 4 EL1h/EL1t sync/irq slots (+0x200,+0x280,+0x300,
# +0x380 and +0x000,+0x080,+0x100,+0x180) start with the same first instruction.
import capstone
TXTK="/Users/maliosdark/darwin-vm/firmware/exclave_comp/txtk"; VMBASE=0xc0000000
RXPHYS=0x10006884000
TEXT_LO=0xc0001200; TEXT_HI=0xc04ea8e8
data=open(TXTK,'rb').read()
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
def first(va):
    off=va-VMBASE
    if off<0 or off+4>len(data): return None
    try: return next(md.disasm(data[off:off+4],va,count=1))
    except StopIteration: return None
cands=[]
va=(TEXT_LO+0x7ff)&~0x7ff
while va<TEXT_HI:
    slots=[first(va+0x80*i) for i in range(16)]
    if all(s is not None for s in slots):
        mnem=[s.mnemonic for s in slots]
        # heuristic: at least the last 8 (EL1h + lower-EL) sync/irq entries are
        # real handlers; look for repeating first-instruction across groups of 4
        def grp(a,b,c,d):
            return len({mnem[a],mnem[b],mnem[c],mnem[d]})==1 and mnem[a] not in ("udf","brk","bl")
        # groups: cur EL SPx sync/irq/fiq/serr = slots 4..7 (+0x200..+0x380)
        if grp(4,5,6,7) or grp(0,1,2,3):
            # exclude tables full of the same nop-like op everywhere
            firstops=set((s.mnemonic,s.op_str) for s in slots)
            cands.append((va,mnem))
    va+=0x800
print("candidates:",len(cands))
for va,mnem in cands[:40]:
    print("0x%08x (phys 0x%011x)  slot mnems: %s"%(va, RXPHYS+(va-VMBASE), " ".join(mnem)))
