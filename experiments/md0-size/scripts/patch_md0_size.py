#!/usr/bin/env python3
"""
DESIGN-ONLY patcher for the md0 32-bit size truncation in iOS 27 bootkc.

Widens the three `mdSize << 12` (page-count -> byte-size) computations in
XNU's memdev.c md-device driver from 32-bit to 64-bit, so md0 reports the
full 9.3 GB instead of (size & 0xFFFFFFFF) = 1.36 GB.

Guardrails (vphone-cli CLAUDE.md, "Kernel patcher guardrails"):
  - NO hardcoded file offsets/vmaddrs in patch LOGIC: sites are located by
    semantic anchors (a 32-bit page->byte `<<12` of a value that was loaded
    from the mdSize field `[entry+8]`, inside memdev.c which xrefs mdev[]).
  - Replacement bytes come from Keystone (asm of the widened x-form), never a
    hand-computed bit flip (the LSL-immediate re-encoding is NOT a single bit).
  - Every change is disassembled before/after and logged.

This module DOES NOT WRITE the live tree. It prints the plan and, with
--emit-bytes OUT, writes a patched COPY. Point KC (in macho_map.py) at a
WORKING COPY of bootkc to test.
"""
import sys, re, argparse
sys.path.insert(0, "/Users/maliosdark/ios27-cl4-secure-world/experiments/md0-size/scripts")
from macho_map import load, v2f
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM); cs.detail = True
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)


def asm(text):
    enc, _ = ks.asm(text)
    return bytes(enc)


def dis1(b, addr=0):
    return next(cs.disasm(b, addr))


def norm(ins):
    return f"{ins.mnemonic} {ins.op_str}".replace(" ", "")


def find_mdev_size_shift_sites(data, all_segs):
    """Semantic finder. Detect a 32-bit page->byte conversion of the mdSize
    field: `lsl w<s>,w<s>,#0xc` or `add w<d>,w<x>,w<s>,lsl #12`, where w<s> was
    loaded a few instructions earlier by `ldr w<s>,[x<e>,#8]` (the uint32
    mdSize page-count field). Restricted to com.apple.kernel __TEXT_EXEC."""
    sites = []
    for s in all_segs:
        if s.owner != "com.apple.kernel" or not (s.initprot & 0x4) or s.filesize == 0:
            continue
        # ARM64 is fixed 4-byte; decode each slot independently so a literal
        # pool cannot desync the instruction stream (linear sweep would).
        code = data[s.fileoff:s.fileoff + s.filesize]
        insns = []
        for k in range(0, len(code) - 3, 4):
            g = list(cs.disasm(code[k:k + 4], s.vmaddr + k))
            insns.append(g[0] if g else None)
        for i, ins in enumerate(insns):
            if ins is None:
                continue
            t = norm(ins)
            szreg = None; widened = None
            m = re.match(r"lsl(w\d+),(w\d+),#0xc$", t)
            if m and m.group(1) == m.group(2):
                szreg = m.group(1); x = "x" + szreg[1:]
                widened = f"lsl {x}, {x}, #0xc"
            m = re.match(r"add(w\d+),(w\d+),(w\d+),lsl#12$", t)
            if m and m.group(1) == m.group(3):
                szreg = m.group(3); a = m.group(1); b = m.group(2)
                widened = f"add x{a[1:]}, x{b[1:]}, x{szreg[1:]}, lsl #12"
            if not szreg:
                continue
            # confirm szreg was loaded from [x,#8] within the previous 4 insns
            ok = False
            for j in range(max(0, i - 4), i):
                pj = insns[j]
                if pj is not None and re.match(rf"ldr{szreg},\[x\d+,#8\]$", norm(pj)):
                    ok = True; break
            if ok:
                sites.append(dict(shift_va=ins.address, orig=f"{ins.mnemonic} {ins.op_str}",
                                  widened=widened, is_add=widened.startswith("add x")))
    return sites


def build_plan(data, all_segs):
    """Full widen plan. The DKIOCGETBLOCKCOUNT `add ...,lsl #12` blockcount form
    additionally needs the two dependent ops (`sub w,#1`, `udiv w,w,w`) widened;
    they are the next two instructions and are checked semantically."""
    plan = []
    for site in find_mdev_size_shift_sites(data, all_segs):
        va = site["shift_va"]; fo, _ = v2f(all_segs, va)
        plan.append((va, fo, site["orig"], site["widened"]))
        if site["is_add"]:
            for off in (4, 8):
                d = dis1(data[fo + off:fo + off + 4], va + off)
                t = f"{d.mnemonic} {d.op_str}"
                if d.mnemonic in ("sub", "udiv") and "w" in d.op_str:
                    plan.append((va + off, fo + off, t, t.replace("w", "x")))
    return plan


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit-bytes", metavar="OUT", help="write patched copy to OUT")
    a = ap.parse_args()
    data, all_segs, entries = load()
    plan = build_plan(data, all_segs)
    print(f"# {len(plan)} instruction widen edits (w->x):")
    buf = bytearray(data)
    for va, fo, orig, widened in sorted(plan):
        new = asm(widened); rd = dis1(new, va); cur = data[fo:fo + 4]
        assert len(new) == 4
        print(f"  va={va:#x} fo={fo:#x}")
        print(f"     - {orig}   [{cur.hex()}]")
        print(f"     + {rd.mnemonic} {rd.op_str}   [{new.hex()}]")
        buf[fo:fo + 4] = new
    if a.emit_bytes:
        open(a.emit_bytes, "wb").write(bytes(buf))
        print(f"# wrote {a.emit_bytes}")
    else:
        print("# (design run; pass --emit-bytes OUT to write a patched COPY)")
