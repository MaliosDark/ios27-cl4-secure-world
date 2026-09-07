#!/usr/bin/env python3
import sys,struct
KC="/Users/maliosdark/darwin-vm/firmware/bootkc"; D=open(KC,"rb").read()
ncmds,=struct.unpack("<I",D[16:20]); off=32; SEGS=[]
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",D[off:off+8])
    if cmd==0x19:
        n=D[off+8:off+24].split(b"\0")[0].decode()
        vm,vs,fo,fs=struct.unpack("<QQQQ",D[off+24:off+56]); SEGS.append((n,vm,vs,fo,fs))
    off+=cs
def f2v(f):
    for n,vm,vs,fo,fs in SEGS:
        if fo<=f<fo+fs: return vm+(f-fo)
    return None
def seg(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs: return n
    return "?"
IMGBASE=0xfffffff007004000
target=int(sys.argv[1],0)
toff=target-IMGBASE
print(f"# target {target:#x} image-offset {toff:#x}")
for n,vm,vs,fo,fs in SEGS:
    b=D[fo:fo+fs]
    for i in range(0,len(b)-8,8):
        val=struct.unpack("<Q",b[i:i+8])[0]
        low=val & 0xffffffff
        low36=val & 0xfffffffff
        if low==toff or low36==toff or low==(target&0xffffffff):
            print(f"{f2v(fo+i):#011x} fo={fo+i:#09x} raw={val:#018x} [{n}]")
