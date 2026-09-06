#!/usr/bin/env python3
"""Resyncing scanner: step 4 bytes at a time over a vmaddr range, decode one
insn, keep a rolling adrp/add register map, and report accesses to a target EA
(str/ldr [reg,#disp]) and/or BL to a target. Robust against literal pools.

Usage:
  scan.py ea   <page> <disp>        # find str/ldr to page+disp
  scan.py bl   <target>             # find bl/b to target
  scan.py ea   <page> <disp> <lo> <hi>   # limit range (static vmaddrs)
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

KC="/Users/maliosdark/darwin-vm/firmware/bootkc"
DATA=open(KC,"rb").read()
ncmds,=struct.unpack("<I",DATA[16:20]); off=32; SEGS=[]
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",DATA[off:off+8])
    if cmd==0x19:
        name=DATA[off+8:off+24].split(b"\0")[0].decode()
        vm,vs,fo,fs=struct.unpack("<QQQQ",DATA[off+24:off+56]); SEGS.append((name,vm,vs,fo,fs))
    off+=cs
def v2f(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs and v-vm<fs: return fo+(v-vm)
    return None

md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
te=[s for s in SEGS if s[0]=="__TEXT_EXEC"][0]

def scan(kind, target=None, page=None, disp=0, lo=None, hi=None):
    lo = lo or te[1]; hi = hi or te[1]+te[4]
    regs={}
    a=lo
    while a < hi:
        fo=v2f(a)
        if fo is None: a+=4; continue
        blk=DATA[fo:fo+min(0x20000,(hi-a))]
        progressed=False
        last=a-4
        for ins in md.disasm(blk, a):
            progressed=True; last=ins.address
            m=ins.mnemonic; ops=ins.operands
            ffo=v2f(ins.address)
            if m=="adrp":
                regs[ops[0].reg]=ops[1].imm & 0xffffffffffffffff
            elif m=="add" and len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM and ops[1].reg in regs:
                regs[ops[0].reg]=regs[ops[1].reg]+ops[2].imm
            elif kind=="ea" and m in ("str","ldr","stur","ldur","strb","ldrb") and ops and ops[-1].type==ARM64_OP_MEM:
                b=ops[-1].mem.base
                if b in regs:
                    ea=regs[b]+ops[-1].mem.disp
                    if ea==page+disp:
                        isw=m.startswith("st")
                        print(f"{ins.address:#011x} fo={ffo:#09x} {m:5} {ins.op_str}  -> {ea:#x} {'WRITE' if isw else 'read'}")
                if ops[0].type==ARM64_OP_REG and not m.startswith("st"): regs.pop(ops[0].reg,None)
            elif kind=="bl" and m in ("bl","b") and ops and ops[0].type==ARM64_OP_IMM:
                if ops[0].imm==target:
                    print(f"{ins.address:#011x} fo={ffo:#09x} {m} {ins.op_str}")
            else:
                if ops and ops[0].type==ARM64_OP_REG and m not in ("cmp","cmn","tst"):
                    regs.pop(ops[0].reg,None)
        a = last+4 if progressed else a+4

if __name__=="__main__":
    k=sys.argv[1]
    if k=="ea":
        page=int(sys.argv[2],0); disp=int(sys.argv[3],0)
        lo=int(sys.argv[4],0) if len(sys.argv)>4 else None
        hi=int(sys.argv[5],0) if len(sys.argv)>5 else None
        scan("ea",page=page,disp=disp,lo=lo,hi=hi)
    elif k=="bl":
        scan("bl",target=int(sys.argv[2],0))
