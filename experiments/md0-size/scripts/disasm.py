#!/usr/bin/env python3
"""Disassemble a VA range from bootkc, annotating adrp+add string/const refs,
bl targets, and highlighting w vs x register loads."""
import sys
sys.path.insert(0,"/Users/maliosdark/ios27-cl4-secure-world/experiments/md0-size/scripts")
from macho_map import load, v2f, f2v
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_OP_REG, ARM64_OP_IMM

data, all_segs, entries = load()
md=Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True

def cstr_at(va):
    fo,s=v2f(all_segs,va)
    if fo is None: return None
    end=data.find(b'\0',fo)
    if end-fo>80 or end<0: return None
    try: return data[fo:end].decode('latin1')
    except: return None

def find_prologue(va, back=0x400):
    """scan backwards for stp x29,x30/ sub sp or 'ret' preceding to find func start."""
    fo,s=v2f(all_segs,va)
    start_fo=fo-back
    got=list(md.disasm(data[start_fo:fo+4], s.vmaddr+(start_fo-s.fileoff)))
    # find last 'ret' or 'stp' with sp before va -> function start = after last ret
    last_ret=None
    for insn in got:
        if insn.mnemonic in ("ret","retab","retaa") or (insn.mnemonic=="b" and False):
            last_ret=insn.address
    return last_ret

def dump(va_start, va_end):
    fo,s=v2f(all_segs,va_start)
    length=va_end-va_start
    code=data[fo:fo+length+4]
    adrp={}
    for insn in md.disasm(code, va_start):
        fo_i,_=v2f(all_segs,insn.address)
        note=""
        ops=insn.operands
        if insn.id==ARM64_INS_ADRP and len(ops)==2:
            adrp[ops[0].reg]=ops[1].imm
        elif insn.id==ARM64_INS_ADD and len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM and ops[1].reg in adrp:
            tv=adrp[ops[1].reg]+ops[2].imm
            cs=cstr_at(tv)
            note=f"  ; ={tv:#x}" + (f' "{cs}"' if cs else "")
        if insn.mnemonic in ("bl","b") and insn.op_str.startswith("#"):
            tgt=int(insn.op_str[1:],16)
            note+=f"  ; -> {tgt:#x}"
        print(f"{insn.address:#x} [{fo_i:#08x}] {insn.mnemonic:8s} {insn.op_str}{note}")

if __name__=="__main__":
    a=int(sys.argv[1],16); b=int(sys.argv[2],16)
    dump(a,b)
