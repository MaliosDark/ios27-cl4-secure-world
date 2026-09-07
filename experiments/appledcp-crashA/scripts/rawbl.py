#!/usr/bin/env python3
"""Definitive raw scan of __TEXT_EXEC for BL/B (and BLR-less) branches whose
computed target == given static vmaddr. Usage: rawbl.py <target>"""
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
target=int(sys.argv[1],0)
for n,vm,vs,fo,fs in SEGS:
    if n!="__TEXT_EXEC": continue
    b=D[fo:fo+fs]
    for i in range(0,len(b)-4,4):
        w=struct.unpack("<I",b[i:i+4])[0]
        op=w & 0xFC000000
        if op in (0x94000000,0x14000000):  # BL / B
            imm=w & 0x03FFFFFF
            if imm & 0x02000000: imm-=0x04000000
            pc=vm+i
            tgt=pc+imm*4
            if tgt==target:
                kind="BL" if op==0x94000000 else "B "
                print(f"{pc:#011x} fo={fo+i:#09x} {kind} -> {target:#x}")
