#!/usr/bin/env python3
"""Parse LC_FILESET_ENTRY kexts and map a static vmaddr to its owning kext by
walking each entry's inner Mach-O segments. Usage: fileset.py <vmaddr> [more...]"""
import sys, struct
KC="/Users/maliosdark/darwin-vm/firmware/bootkc"; D=open(KC,"rb").read()
# top-level seg map (vmaddr->fileoff)
ncmds,=struct.unpack("<I",D[16:20]); off=32; TOP=[]
FSE=[]
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",D[off:off+8])
    if cmd==0x19:
        n=D[off+8:off+24].split(b"\0")[0].decode(); vm,vs,fo,fs=struct.unpack("<QQQQ",D[off+24:off+56]); TOP.append((n,vm,vs,fo,fs))
    elif cmd==0x80000035:  # LC_FILESET_ENTRY
        vmaddr,fileoff=struct.unpack("<QQ",D[off+8:off+24])
        entry_id_off,=struct.unpack("<I",D[off+24:off+28])
        name=D[off+entry_id_off:D.find(b"\0",off+entry_id_off)].decode()
        FSE.append((vmaddr,fileoff,name))
    off+=cs
def top_v2f(v):
    for n,vm,vs,fo,fs in TOP:
        if vm<=v<vm+vs and v-vm<fs: return fo+(v-vm)
    return None
def kext_segs(fileoff):
    # parse inner macho at file offset
    magic,=struct.unpack("<I",D[fileoff:fileoff+4])
    if magic!=0xfeedfacf: return []
    nc,=struct.unpack("<I",D[fileoff+16:fileoff+20]); o=fileoff+32; segs=[]
    for _ in range(nc):
        cmd,cs=struct.unpack("<II",D[o:o+8])
        if cmd==0x19:
            n=D[o+8:o+24].split(b"\0")[0].decode(); vm,vs,cfo,fsz=struct.unpack("<QQQQ",D[o+24:o+56]); segs.append((n,vm,vs))
        o+=cs
    return segs
def owner(v):
    best=None
    for vmaddr,fileoff,name in FSE:
        for sn,svm,svs in kext_segs(fileoff):
            if svm<=v<svm+svs:
                return name,sn,svm,svs
    return None
if __name__=="__main__":
    if len(sys.argv)==1:
        for vmaddr,fileoff,name in sorted(FSE):
            print(f"{vmaddr:#014x} fo={fileoff:#x} {name}")
    else:
        for a in sys.argv[1:]:
            v=int(a,0); o=owner(v)
            if o: print(f"{v:#x} -> {o[0]}  seg {o[1]} [{o[2]:#x}..{o[2]+o[3]:#x}]")
            else: print(f"{v:#x} -> (no kext; top-level {[n for n,vm,vs,fo,fs in TOP if vm<=v<vm+vs]})")
