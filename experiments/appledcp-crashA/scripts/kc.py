#!/usr/bin/env python3
"""kc.py -- capstone disassembly helper for the iOS27 bootkc FILESET.

Builds the top-level segment map from the Mach-O load commands (no hardcoded
offsets) so any STATIC vmaddr (runtime - 0x20000000) can be mapped to a file
offset and disassembled. Also decodes ADRP+ADD/LDR page-relative xrefs.

Usage:
  kc.py map                       # print segment table
  kc.py dis <static_vmaddr> [n]   # disassemble n instrs (default 40)
  kc.py disr <runtime_vmaddr> [n] # same but takes a runtime addr (slide 0x20000000)
  kc.py f2v <fileoff>             # file offset -> static vmaddr
  kc.py v2f <static_vmaddr>       # static vmaddr -> file offset
  kc.py xref <static_target> [start] [end]  # scan for adrp/adr xrefs to target page
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM

KC = "/Users/maliosdark/darwin-vm/firmware/bootkc"
SLIDE = 0x20000000

def load():
    data = open(KC, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    assert magic in (0xfeedfacf,), hex(magic)
    ncmds, = struct.unpack("<I", data[16:20])
    off = 32  # 64-bit header
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[off:off+8])
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off+8:off+24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack("<QQQQ", data[off+24:off+56])
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return data, segs

DATA, SEGS = load()

def v2f(v):
    for name, vmaddr, vmsize, fileoff, filesize in SEGS:
        if vmaddr <= v < vmaddr + vmsize:
            rel = v - vmaddr
            if rel < filesize:
                return fileoff + rel
            return None  # in bss / zerofill
    return None

def f2v(f):
    for name, vmaddr, vmsize, fileoff, filesize in SEGS:
        if fileoff <= f < fileoff + filesize:
            return vmaddr + (f - fileoff)
    return None

def segname(v):
    for name, vmaddr, vmsize, fileoff, filesize in SEGS:
        if vmaddr <= v < vmaddr + vmsize:
            return name
    return "?"

def dis(v, n=40):
    fo = v2f(v)
    if fo is None:
        print(f"// {v:#x} in {segname(v)} is bss/unmapped (no file bytes)")
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    code = DATA[fo:fo+n*4]
    for ins in md.disasm(code, v):
        print(f"{ins.address:#011x}  fo={v2f(ins.address):#09x}  {ins.mnemonic:<8} {ins.op_str}")

def xref(target, start=None, end=None):
    # scan for adrp Xn, page ; add/ldr referencing that page -> target
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    tpage = target & ~0xfff
    # limit to __TEXT_EXEC by default
    if start is None:
        for name, vmaddr, vmsize, fileoff, filesize in SEGS:
            if name == "__TEXT_EXEC":
                start, end = vmaddr, vmaddr+filesize
    fo = v2f(start)
    code = DATA[fo:v2f(end-4)+4]
    adrp = {}
    hits = 0
    for ins in md.disasm(code, start):
        if ins.mnemonic == "adrp":
            ops = ins.operands
            adrp[ops[0].reg] = ins.imm if hasattr(ins,'imm') else ops[1].imm
            adrp[ops[0].reg] = ops[1].imm
        elif ins.mnemonic in ("add","ldr") and len(ins.operands) >= 2:
            base = ins.operands[1].reg if ins.operands[1].type==ARM64_OP_REG else None
            if base in adrp:
                if ins.mnemonic == "add" and ins.operands[2].type==ARM64_OP_IMM:
                    ea = adrp[base] + ins.operands[2].imm
                elif ins.mnemonic == "ldr" and ins.operands[1].type==ARM64_OP_MEM:
                    ea = adrp[base] + ins.operands[1].mem.disp
                else:
                    continue
                if ea == target or (ea & ~0xfff)==tpage:
                    print(f"{ins.address:#011x} fo={v2f(ins.address):#09x} {ins.mnemonic} {ins.op_str}  -> {ea:#x}")
                    hits += 1
                    if hits > 200: break

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "map":
        for name, vmaddr, vmsize, fileoff, filesize in SEGS:
            print(f"{name:<16} vm={vmaddr:#014x}..{vmaddr+vmsize:#014x} fo={fileoff:#010x} fsz={filesize:#x}")
    elif cmd == "dis":
        dis(int(sys.argv[2],0), int(sys.argv[3]) if len(sys.argv)>3 else 40)
    elif cmd == "disr":
        dis(int(sys.argv[2],0)-SLIDE, int(sys.argv[3]) if len(sys.argv)>3 else 40)
    elif cmd == "v2f":
        print(hex(v2f(int(sys.argv[2],0))))
    elif cmd == "f2v":
        print(hex(f2v(int(sys.argv[2],0))))
    elif cmd == "xref":
        a=[int(x,0) for x in sys.argv[2:]]
        xref(*a)
