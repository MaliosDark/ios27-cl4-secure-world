#!/usr/bin/env python3
# Word-by-word scan of CL4 __TEXT for key sysreg writes/reads, svc, brk, eret.
import capstone, sys
TXTK = "/Users/maliosdark/darwin-vm/firmware/exclave_comp/txtk"
VMBASE = 0xc0000000
RXPHYS = 0x10006884000
data = open(TXTK, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

TARGET = {"vbar_el1","tpidr_el0","tpidrro_el0","vbar_el2","sctlr_el1",
          "cpacr_el1","tpidr_el1","spsr_el1","elr_el1","sp_el0","daif",
          "mair_el1","ttbr0_el1","ttbr1_el1","tcr_el1","spsel","vbar_el3"}
mode = sys.argv[1] if len(sys.argv) > 1 else "msr"

# CL4 __TEXT executable content region; scan generously across code.
# Sections are within file; step 4 bytes, decode single insn each.
N = len(data)
off = 0
while off + 4 <= N:
    va = VMBASE + off
    try:
        insn = next(md.disasm(data[off:off+4], va, count=1))
    except StopIteration:
        off += 4
        continue
    m = insn.mnemonic; ops = insn.op_str
    phys = RXPHYS + off
    hit = False
    if mode == "msr" and m == "msr":
        reg = ops.split(",")[0].strip().lower()
        if reg in TARGET: hit = True
    elif mode == "mrs" and m == "mrs":
        reg = ops.split(",")[-1].strip().lower()
        if reg in TARGET: hit = True
    elif mode == "svc" and m.startswith("svc"): hit = True
    elif mode == "eret" and m.startswith("eret"): hit = True
    elif mode == "hvc" and m.startswith("hvc"): hit = True
    if hit:
        print("0x%08x (fo 0x%06x / phys 0x%011x)  %-6s %s" % (va, off, phys, m, ops))
    off += 4
