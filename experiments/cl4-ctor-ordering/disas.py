#!/usr/bin/env python3
# CL4 (__TEXT/txtk) disassembler helper.
# vmaddr base 0xc0000000; file offset = vmaddr - 0xc0000000.
# phys rx base = 0x10006884000; phys = rx + (vmaddr - 0xc0000000).
import sys, capstone

TXTK = "/Users/maliosdark/darwin-vm/firmware/exclave_comp/txtk"
VMBASE = 0xc0000000
RXPHYS = 0x10006884000

def load():
    with open(TXTK, "rb") as f:
        return f.read()

def disas(vmaddr, count=40, data=None):
    if data is None:
        data = load()
    off = vmaddr - VMBASE
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    code = data[off:off + count*4]
    out = []
    for insn in md.disasm(code, vmaddr):
        phys = RXPHYS + (insn.address - VMBASE)
        out.append("0x%08x  (fo 0x%06x / phys 0x%011x)  %-8s %s" % (
            insn.address, insn.address - VMBASE, phys, insn.mnemonic, insn.op_str))
        if len(out) >= count:
            break
    return "\n".join(out)

if __name__ == "__main__":
    va = int(sys.argv[1], 0)
    n  = int(sys.argv[2], 0) if len(sys.argv) > 2 else 40
    print(disas(va, n))
