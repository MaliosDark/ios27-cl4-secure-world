#!/usr/bin/env python3
# Scan CL4 __TEXT for msr writes to key sysregs, mrs reads, svc, and eret.
import capstone
TXTK = "/Users/maliosdark/darwin-vm/firmware/exclave_comp/txtk"
VMBASE = 0xc0000000
RXPHYS = 0x10006884000
data = open(TXTK, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True

TARGET_MSR = {"vbar_el1", "tpidr_el0", "tpidrro_el0", "vbar_el2", "sctlr_el1",
              "cpacr_el1", "tpidr_el1", "spsr_el1", "elr_el1", "sp_el0",
              "mair_el1", "ttbr0_el1", "ttbr1_el1", "tcr_el1"}
want = set()
import sys
mode = sys.argv[1] if len(sys.argv) > 1 else "msr"
for insn in md.disasm(data, VMBASE):
    m = insn.mnemonic
    ops = insn.op_str
    phys = RXPHYS + (insn.address - VMBASE)
    if mode == "msr" and m == "msr":
        reg = ops.split(",")[0].strip().lower()
        if reg in TARGET_MSR:
            print("MSR  0x%08x (fo 0x%06x / phys 0x%011x)  %s %s" % (insn.address, insn.address-VMBASE, phys, m, ops))
    elif mode == "svc" and m == "svc":
        print("SVC  0x%08x (fo 0x%06x / phys 0x%011x)  %s %s" % (insn.address, insn.address-VMBASE, phys, m, ops))
    elif mode == "eret" and m in ("eret", "eretaa", "eretab"):
        print("ERET 0x%08x (fo 0x%06x / phys 0x%011x)  %s %s" % (insn.address, insn.address-VMBASE, phys, m, ops))
    elif mode == "mrs" and m == "mrs":
        reg = ops.split(",")[-1].strip().lower()
        if reg in TARGET_MSR:
            print("MRS  0x%08x (fo 0x%06x / phys 0x%011x)  %s %s" % (insn.address, insn.address-VMBASE, phys, m, ops))
