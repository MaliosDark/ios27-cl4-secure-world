#!/usr/bin/env python3
# reg_keys.py -- for each BL to register (0xc00a1e20), backtrack x0 to a static
# node (adrp+add) and read {key1@+8, key2@+0x10, value@+0x18} from __DATA; also
# show the ~14 insns before the call so dynamic nodes are visible.
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM
import cl4dis

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
SITES = cl4dis.find_bl(0xc00a1e20)


def track_x0(site, back=20):
    start = site - back * 4
    x = {}          # reg -> value (for adrp/add const tracking)
    node = None
    lines = []
    for i in md.disasm(cl4dis.read_vm(start, back * 4), start):
        m, o = i.mnemonic, i.op_str
        if m == "adrp":
            rd = i.operands[0].value.reg
            x[rd] = i.operands[1].value.imm
        elif m == "add" and len(i.operands) == 3 and i.operands[1].type == ARM64_OP_REG \
                and i.operands[2].type == ARM64_OP_IMM:
            rs = i.operands[1].value.reg
            if rs in x:
                x[i.operands[0].value.reg] = x[rs] + i.operands[2].value.imm
        elif m == "mov" and len(i.operands) == 2 and i.operands[1].type == ARM64_OP_REG:
            rs = i.operands[1].value.reg
            if rs in x:
                x[i.operands[0].value.reg] = x[rs]
        lines.append("      0x%08x  %-6s %s" % (i.address, m, o))
        if i.address == site:
            # x0 is reg id for w0/x0 == 0
            for rid, val in x.items():
                if i.reg_name(rid) in ("x0", "w0"):
                    node = val
            break
    return node, lines


print("== register(node) call sites: node keys ==")
for s in SITES:
    node, lines = track_x0(s)
    print("\nBL@0x%08x  func 0x%08x" % (s, cl4dis.func_start(s)))
    if node is not None:
        k1 = struct.unpack('<I', cl4dis.read_vm(node + 8, 4))[0]
        k2 = struct.unpack('<I', cl4dis.read_vm(node + 0x10, 4))[0]
        val = struct.unpack('<Q', cl4dis.read_vm(node + 0x18, 8))[0]
        nxt = struct.unpack('<Q', cl4dis.read_vm(node, 8))[0]
        print("   STATIC node @0x%08x  key1=%d key2=%d value=0x%x next=0x%x"
              % (node, k1, k2, val, nxt))
    else:
        print("   (dynamic node - see trace)")
        for l in lines[-10:]:
            print(l)
