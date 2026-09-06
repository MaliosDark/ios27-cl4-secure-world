#!/usr/bin/env python3
"""Find ADRP+ADD / ADR / ADRP+LDR xrefs to a target VA across ALL exec segments."""
import sys
sys.path.insert(0,"/Users/maliosdark/ios27-cl4-secure-world/experiments/md0-size/scripts")
from macho_map import load, f2v, v2f
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_INS_ADR, ARM64_INS_LDR, ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

data, all_segs, entries = load()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True

def exec_segs():
    for s in all_segs:
        if (s.initprot & 0x4) and s.filesize>0:
            yield s

def scan_targets(targets):
    """targets: set of VAs. Return list of (site_va, kind, target, seg)."""
    res=[]
    for s in exec_segs():
        code = data[s.fileoff:s.fileoff+s.filesize]
        base = s.vmaddr
        # track adrp results per register
        adrp_val={}
        for insn in md.disasm(code, base):
            m=insn.id
            if m==ARM64_INS_ADRP:
                ops=insn.operands
                if len(ops)==2 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_IMM:
                    adrp_val[ops[0].reg]=ops[1].imm
            elif m==ARM64_INS_ADD:
                ops=insn.operands
                if len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM and ops[1].reg in adrp_val:
                    tv=adrp_val[ops[1].reg]+ops[2].imm
                    if tv in targets:
                        res.append((insn.address, "adrp+add", tv, s))
            elif m==ARM64_INS_ADR:
                ops=insn.operands
                if len(ops)==2 and ops[1].type==ARM64_OP_IMM and ops[1].imm in targets:
                    res.append((insn.address,"adr",ops[1].imm,s))
            elif m==ARM64_INS_LDR:
                ops=insn.operands
                if len(ops)==2 and ops[1].type==ARM64_OP_MEM and ops[1].mem.base in adrp_val:
                    tv=adrp_val[ops[1].mem.base]+ops[1].mem.disp
                    if tv in targets:
                        res.append((insn.address,"adrp+ldr(GOT@)",tv,s))
    return res

if __name__=="__main__":
    targets={
        0xfffffff0070ca463:"ramdisk params @%s:%d",
        0xfffffff0070ca45b:"RAMDisk",
        0xfffffff00706e833:"memdev.c",
        0xfffffff00706e910:"md%d",
        0xfffffff0070ae96a:"-rootdmg-ramdisk",
        0xfffffff0070aea22:"imageboot_mount_ramdisk",
        0xfffffff00706e7e7:"mdevadd overlap",
        0xfffffff00706e83c:"mdevadd morethan",
    }
    res=scan_targets(set(targets))
    for site,kind,tv,s in sorted(res):
        fo,_=v2f(all_segs,site)
        print(f"site va={site:#x} fo={fo:#x} [{s.owner}/{s.name}] {kind} -> {tv:#x} ({targets[tv]!r})")
