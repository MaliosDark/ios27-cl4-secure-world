#!/usr/bin/env python3
"""Find str/ldr accesses to a global var (adrp page + disp) across __TEXT_EXEC.
Usage: find_writes.py <page_base> <disp> [mode=str|ldr|both]
Tracks adrp reg -> page, then reports str/ldr with that base and matching disp,
including adrp+add (reg holds page+off) then str/ldr [reg,#d]."""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

KC="/Users/maliosdark/darwin-vm/firmware/bootkc"
DATA=open(KC,"rb").read()
ncmds,=struct.unpack("<I",DATA[16:20])
off=32; SEGS=[]
for _ in range(ncmds):
    cmd,cmdsize=struct.unpack("<II",DATA[off:off+8])
    if cmd==0x19:
        name=DATA[off+8:off+24].split(b"\0")[0].decode()
        vm,vs,fo,fs=struct.unpack("<QQQQ",DATA[off+24:off+56])
        SEGS.append((name,vm,vs,fo,fs))
    off+=cmdsize
def v2f(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs and v-vm<fs: return fo+(v-vm)
    return None

page=int(sys.argv[1],0); target=page + (int(sys.argv[2],0) if len(sys.argv)>2 else 0)
mode=sys.argv[3] if len(sys.argv)>3 else "both"
te=[s for s in SEGS if s[0]=="__TEXT_EXEC"][0]
start=te[1]; fo=te[3]; fs=te[4]
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
# reg -> (kind, value): kind 'page' value=pagebase ; kind 'addr' value=page+off
regs={}
code=DATA[fo:fo+fs]
for ins in md.disasm(code,start):
    m=ins.mnemonic; ops=ins.operands
    if m=="adrp":
        regs[ops[0].reg]=("page",ops[1].imm)
    elif m=="add" and len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM:
        b=ops[1].reg
        if b in regs and regs[b][0]=="page":
            regs[ops[0].reg]=("addr",regs[b][1]+ops[2].imm)
        else:
            regs.pop(ops[0].reg,None)
    elif m in ("str","ldr","stur","ldur") and len(ops)>=2 and ops[-1].type==ARM64_OP_MEM:
        mem=ops[-1].mem; b=mem.base
        ea=None
        if b in regs:
            k,val=regs[b]
            if k=="page": ea=val+mem.disp
            elif k=="addr": ea=val+mem.disp
        if ea==target:
            isw = m.startswith("st")
            if mode=="both" or (mode=="str" and isw) or (mode=="ldr" and not isw):
                print(f"{ins.address:#011x} fo={v2f(ins.address):#09x} {m:5} {ins.op_str}   -> {ea:#x} {'WRITE' if isw else 'read'}")
        # writing to a base reg via load clobbers tracking
        if ops[0].type==ARM64_OP_REG and not m.startswith("st"):
            regs.pop(ops[0].reg,None)
    else:
        # dest reg clobbered
        if ops and ops[0].type==ARM64_OP_REG:
            regs.pop(ops[0].reg,None)
