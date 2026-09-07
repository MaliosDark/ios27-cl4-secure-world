#!/usr/bin/env python3
"""For each `pacia x16,x17` (disc 0xba5) sign site, show a few instrs after to
see where x16 is stored (registrar detection: str x16,[Xn,#8])."""
import sys,struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
KC="/Users/maliosdark/darwin-vm/firmware/bootkc"; D=open(KC,"rb").read()
ncmds,=struct.unpack("<I",D[16:20]); off=32; SEGS=[]
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",D[off:off+8])
    if cmd==0x19:
        n=D[off+8:off+24].split(b"\0")[0].decode()
        vm,vs,fo,fs=struct.unpack("<QQQQ",D[off+24:off+56]); SEGS.append((n,vm,vs,fo,fs))
    off+=cs
def v2f(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs and v-vm<fs: return fo+(v-vm)
    return None
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for a in sys.argv[1:]:
    va=int(a,0); fo=v2f(va)
    print(f"--- sign @ {va:#x} (fo {fo:#x}) ---")
    for ins in md.disasm(D[fo:fo+9*4], va):
        print(f"  {ins.address:#011x} {ins.mnemonic:8} {ins.op_str}")
