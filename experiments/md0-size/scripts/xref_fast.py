#!/usr/bin/env python3
"""Fast manual ADRP/ADD/ADR/LDR(literal) xref scanner over ALL exec segments."""
import sys, struct
sys.path.insert(0,"/Users/maliosdark/ios27-cl4-secure-world/experiments/md0-size/scripts")
from macho_map import load, v2f

data, all_segs, entries = load()

def sxt(v,bits):
    if v & (1<<(bits-1)): return v-(1<<bits)
    return v

def exec_segs():
    for s in all_segs:
        if (s.initprot & 0x4) and s.filesize>0:
            yield s

def find_xrefs(targets):
    """targets: dict va->label. Returns list (site_va,kind,target,seg)."""
    res=[]
    tset=set(targets)
    for s in exec_segs():
        code=data[s.fileoff:s.fileoff+s.filesize]
        n=len(code)//4
        words=struct.unpack_from("<%dI"%n, code, 0)
        adrp_page=[None]*32
        for i in range(n):
            w=words[i]
            pc=s.vmaddr+i*4
            if (w & 0x9F000000)==0x90000000:  # ADRP
                rd=w&0x1f
                immlo=(w>>29)&3
                immhi=(w>>5)&0x7ffff
                imm=sxt((immhi<<2)|immlo,21)
                page=(pc & ~0xfff)+(imm<<12)
                adrp_page[rd]=page
            elif (w & 0x7F800000)==0x11000000 and (w & 0x80000000):  # ADD imm 64-bit (sf=1,0b100010001)
                # decode: [31]=sf,[30]=op,[29]=S,[28:24]=10001
                if ((w>>24)&0x1f)==0x11:
                    rn=(w>>5)&0x1f; rd=w&0x1f
                    sh=(w>>22)&1; imm12=(w>>10)&0xfff
                    if sh: imm12<<=12
                    if adrp_page[rn] is not None:
                        tv=adrp_page[rn]+imm12
                        if tv in tset:
                            res.append((pc,"adrp+add",tv,s))
            elif (w & 0x9F000000)==0x10000000:  # ADR
                rd=w&0x1f
                immlo=(w>>29)&3; immhi=(w>>5)&0x7ffff
                imm=sxt((immhi<<2)|immlo,21)
                tv=pc+imm
                if tv in tset:
                    res.append((pc,"adr",tv,s))
                adrp_page[rd]=None
            elif (w & 0x3B000000)==0x39000000:
                # LDR/STR immediate unsigned offset with base = adrp reg (completes address-of)
                rn=(w>>5)&0x1f
                size=(w>>30)&3
                imm12=(w>>10)&0xfff
                if adrp_page[rn] is not None:
                    tv=adrp_page[rn]+(imm12<<size)
                    if tv in tset:
                        res.append((pc,"adrp+ldr/str@",tv,s))
    return res

if __name__=="__main__":
    targets={
        0xfffffff0070ca463:"ramdisk params @%s:%d",
        0xfffffff0070ca45b:"RAMDisk",
        0xfffffff00706e833:"memdev.c",
        0xfffffff00706e831:"memdev.c-1",
        0xfffffff00706e910:"md%d",
        0xfffffff0070ae96a:"-rootdmg-ramdisk",
        0xfffffff0070aea22:"imageboot_mount_ramdisk",
        0xfffffff00706e7e7:"mdevadd overlap",
        0xfffffff00706e7c8:"mdevadd-page",
    }
    res=find_xrefs(targets)
    print(f"{len(res)} xrefs")
    for site,kind,tv,s in sorted(res,key=lambda r:r[0]):
        fo,_=v2f(all_segs,site)
        print(f"site va={site:#x} fo={fo:#x} [{s.owner}/{s.name}] {kind} -> {tv:#x} ({targets[tv]!r})")
