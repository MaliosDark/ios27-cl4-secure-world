#!/usr/bin/env python3
# find_registrar.py -- locate the per-thread registry REGISTRATION function.
#
# The factory 0xc00a1e70 reads:  x8=[tpidr+0x10]; x9=[x8]=head; node layout
# [+0]=next [+8]=key1(w) [+0x10]=key2(w) [+0x18]=value.  Registration must:
#   * read tpidr_el0 and load the registry object at [+0x10]  (list-head holder)
#   * write a node's {next,key1,key2,value}
#   * link it (store node into [x8] / node->next=old head).
# We scan __TEXT for functions that touch tpidr and store to a node shape, and
# for functions that update the list head at [reg]/[reg+0x10].

import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import cl4dis

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
TXT = cl4dis.TXT
BASE = cl4dis.BASE


def funcs_reading_tpidr():
    """functions (approx) that contain mrs tpidr_el0."""
    out = {}
    for vm, w in cl4dis.iter_text():
        if (w & 0xffffffe0) == 0xd53bd040:            # mrs Xt, tpidr_el0
            f = cl4dis.func_start(vm)
            out.setdefault(f, []).append(vm)
    return out


def scan_node_stores(fstart, span=0x300):
    """within [fstart, fstart+span] look for stores to +8,+0x10,+0x18 (node shape)
    and list-head-style stores. Return the set of (off,mnem) seen."""
    code = cl4dis.read_vm(fstart, span // 4 * 4)
    seen = {"+8": [], "+0x10": [], "+0x18": [], "+0": [], "tpidr": [], "call": []}
    for i in md.disasm(code, fstart):
        m, o = i.mnemonic, i.op_str
        if m == "mrs" and "tpidr_el0" in o:
            seen["tpidr"].append(i.address)
        if m in ("str", "stur"):
            # crude offset parse
            if "#8]" in o or ", #8]" in o:
                seen["+8"].append((i.address, o))
            if "#0x10]" in o:
                seen["+0x10"].append((i.address, o))
            if "#0x18]" in o:
                seen["+0x18"].append((i.address, o))
            if o.endswith("]") and "#" not in o.split("[")[1]:
                seen["+0"].append((i.address, o))
        if m == "bl":
            seen["call"].append((i.address, o))
        if m in ("ret", "retab", "retaa"):
            break
    return seen


if __name__ == "__main__":
    tp = funcs_reading_tpidr()
    print("== %d functions read tpidr_el0 ==" % len(tp))
    cands = []
    for f in sorted(tp):
        s = scan_node_stores(f)
        score = (bool(s["+8"]) + bool(s["+0x10"]) + bool(s["+0x18"]))
        if score >= 2 and s["tpidr"]:
            cands.append((score, f, s))
    print("\n== candidate registrars (store node shape +8/+0x10/+0x18 near tpidr) ==")
    for score, f, s in sorted(cands, reverse=True):
        print("\nfunc 0x%08x  score=%d  tpidr@%s" %
              (f, score, ["0x%x" % a for a in s["tpidr"]]))
        for k in ("+8", "+0x10", "+0x18", "+0"):
            for a, o in s[k][:4]:
                print("    %s  0x%08x  str %s" % (k, a, o))
