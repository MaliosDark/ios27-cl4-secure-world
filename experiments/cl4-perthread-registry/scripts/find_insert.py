#!/usr/bin/env python3
# find_insert.py -- find the singly-linked-list head-insert idiom:
#     ldr  Xold, [Xreg]         ; old head
#     str  Xold, [Xnode]        ; node->next = old head   (node+0)
#     ...
#     str  Xnode, [Xreg]        ; head = node
# and, in the same function, stores to [Xnode,#8]/[+0x10]/[+0x18] (key1,key2,value).
# Also report BL callers of the (2,5) accessor 0xc0098ce0.

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
import cl4dis

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
insns = list(md.disasm(cl4dis.TXT, cl4dis.BASE))
idx = {i.address: n for n, i in enumerate(insns)}


def mem(i):
    if i.mnemonic in ("ldr", "str", "stur", "ldur") and len(i.operands) == 2 \
            and i.operands[1].type == ARM64_OP_MEM and i.operands[0].type == ARM64_OP_REG:
        return (i.reg_name(i.operands[0].value.reg),
                i.reg_name(i.operands[1].value.mem.base),
                i.operands[1].value.mem.disp)
    return None


def scan_head_insert():
    hits = []
    for n, i in enumerate(insns):
        m = mem(i)
        if not m or i.mnemonic not in ("str", "stur") or m[2] != 0:
            continue
        node_reg, reg_reg, _ = m       # str node,[reg]  (head=node)
        # look back for ldr old,[reg] and str old,[node]
        old = None
        node_next_set = False
        for j in range(max(0, n - 12), n):
            mj = mem(insns[j])
            if not mj:
                continue
            if insns[j].mnemonic == "ldr" and mj[1] == reg_reg and mj[2] == 0:
                old = mj[0]
            if insns[j].mnemonic in ("str", "stur") and mj[1] == node_reg and mj[2] == 0 \
                    and old is not None and mj[0] == old:
                node_next_set = True
        if node_next_set:
            # find key/value stores to node_reg nearby
            keys = []
            for j in range(max(0, n - 16), min(len(insns), n + 4)):
                mj = mem(insns[j])
                if mj and insns[j].mnemonic in ("str", "stur") and mj[1] == node_reg \
                        and mj[2] in (8, 0x10, 0x18):
                    keys.append((insns[j].address, insns[j].mnemonic, insns[j].op_str))
            hits.append((cl4dis.func_start(i.address), i.address, node_reg, reg_reg, keys))
    return hits


if __name__ == "__main__":
    print("== head-insert idiom sites ==")
    for f, a, node, reg, keys in scan_head_insert():
        print("\nFUNC 0x%08x  insert@0x%08x  node=%s head=[%s]" % (f, a, node, reg))
        for ka, km, ko in keys:
            print("    key/val  0x%08x  %s %s" % (ka, km, ko))
    print("\n== callers of (2,5) accessor 0xc0098ce0 ==")
    for a in cl4dis.find_bl(0xc0098ce0):
        print("  BL from 0x%08x  (func 0x%08x)" % (a, cl4dis.func_start(a)))
