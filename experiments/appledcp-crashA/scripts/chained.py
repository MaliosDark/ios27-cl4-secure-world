#!/usr/bin/env python3
"""Parse LC_DYLD_CHAINED_FIXUPS (format 8, DYLD_CHAINED_PTR_64_KERNEL_CACHE) and
resolve rebase/auth-rebase pointers. Report pointer locations whose target ==
requested static vmaddr. Usage: chained.py <target_vmaddr> [--dump-owner]"""
import sys,struct
KC="/Users/maliosdark/darwin-vm/firmware/bootkc"; D=open(KC,"rb").read()
ncmds,=struct.unpack("<I",D[16:20]); off=32; SEGS=[]; CF=None
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",D[off:off+8])
    if cmd==0x19:
        n=D[off+8:off+24].split(b"\0")[0].decode()
        vm,vs,fo,fs=struct.unpack("<QQQQ",D[off+24:off+56]); SEGS.append((n,vm,vs,fo,fs))
    elif cmd==0x80000034:
        CF=struct.unpack("<II",D[off+8:off+16])
    off+=cs
def f2v(f):
    for n,vm,vs,fo,fs in SEGS:
        if fo<=f<fo+fs: return vm+(f-fo)
    return None
def seg(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm is not None and vm<=v<vm+vs: return n
    return "?"
IMGBASE=min(vm for n,vm,vs,fo,fs in SEGS)
base=CF[0]; so=base+0x1c
seg_count,=struct.unpack("<I",D[so:so+4])
offs=struct.unpack(f"<{seg_count}I",D[so+4:so+4+4*seg_count])
target=int(sys.argv[1],0)
found=[]; total=0; index={}
for i,o in enumerate(offs):
    if o==0: continue
    p=so+o
    size_,page_size,pfmt,segoff,maxvp=struct.unpack("<IHHQI",D[p:p+20])
    page_count,=struct.unpack("<H",D[p+20:p+22])
    page_start=struct.unpack(f"<{page_count}H",D[p+22:p+22+2*page_count])
    for pi,start in enumerate(page_start):
        if start==0xFFFF: continue
        cur=segoff+pi*page_size+start
        while True:
            raw,=struct.unpack("<Q",D[cur:cur+8]); total+=1
            isauth=(raw>>63)&1
            tgt=IMGBASE+(raw & 0x3FFFFFFF)
            index[f2v(cur)]=(tgt,isauth,raw)
            if tgt==target:
                found.append((f2v(cur),cur,raw,isauth))
            nxt=(raw>>51)&0xFFF
            if nxt==0: break
            cur+=nxt*4
print(f"# parsed {total} chained fixups; target {target:#x}")
for v,fo,raw,isauth in found:
    print(f"{v:#011x} fo={fo:#09x} raw={raw:#018x} auth={isauth} [{seg(v)}]")
if not found: print("# no fixup resolves to target")
