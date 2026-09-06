#!/usr/bin/env python3
# find_reg2.py -- 2-level taint. Track:
#   T0 = value of mrs tpidr_el0
#   T10 = [T0 + 0x10]   (the registry object; factory reads its [+0]=head)
#   Tf8 = [T0 + 0xf8]   (the "current context/domain" pointer)
# Report any STORE through T10 or Tf8 (that is registration into the registry),
# plus which functions load [T0+0x10]/[T0+0xf8] and then store.
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
import cl4dis

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True


def body(fstart, span=0x600):
    out = []
    for i in md.disasm(cl4dis.read_vm(fstart, span), fstart):
        out.append(i)
        if i.mnemonic in ("ret", "retab", "retaa") and len(out) > 4:
            break
    return out


def analyze(fstart):
    ins = body(fstart)
    T0 = set()      # regs == tpidr
    T10 = set()     # regs == [tpidr+0x10] (registry obj)
    Tf8 = set()     # regs == [tpidr+0xf8]
    out = []
    interesting = False
    for i in ins:
        m = i.mnemonic
        ops = i.operands
        # kill overwritten regs (simple): on any def, remove from taint sets unless we re-add
        def dst():
            if ops and ops[0].type == ARM64_OP_REG:
                return ops[0].value.reg
            return None
        if m == "mrs" and "tpidr_el0" in i.op_str:
            r = dst(); T0 = {r};
            T10.discard(r); Tf8.discard(r)
            continue
        if m == "ldr" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
            b = ops[1].value.mem.base; d = ops[1].value.mem.disp; r = dst()
            for s in (T0, T10, Tf8):
                s.discard(r)
            if b in T0 and d == 0x10:
                T10.add(r); interesting = True
                out.append("    0x%08x  ldr regobj <- [tpidr+0x10]" % i.address)
                continue
            if b in T0 and d == 0xf8:
                Tf8.add(r)
                out.append("    0x%08x  ldr ctx <- [tpidr+0xf8]" % i.address)
                continue
            if b in T10:
                out.append("    0x%08x  ldr %s <- [regobj+0x%x]" % (i.address, i.reg_name(r), d))
            continue
        if m in ("str", "stur") and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
            b = ops[1].value.mem.base; d = ops[1].value.mem.disp
            src = i.reg_name(ops[0].value.reg)
            if b in T10:
                out.append("    0x%08x  *** STR %s -> [regobj+0x%x] (registry write) ***"
                           % (i.address, src, d))
                interesting = True
            elif b in Tf8:
                out.append("    0x%08x  STR %s -> [ctx+0x%x]" % (i.address, src, d))
            continue
        # generic def kills taint
        r = dst()
        if r is not None:
            for s in (T0, T10, Tf8):
                s.discard(r)
    return interesting, out


if __name__ == "__main__":
    seen = set()
    for vm, w in cl4dis.iter_text():
        if (w & 0xffffffe0) == 0xd53bd040:
            seen.add(cl4dis.func_start(vm))
    for f in sorted(seen):
        interesting, out = analyze(f)
        writes = [l for l in out if "registry write" in l]
        if writes:
            print("\nFUNC 0x%08x (phys 0x%x)" % (f, cl4dis.phys(f)))
            for l in out:
                print(l)
