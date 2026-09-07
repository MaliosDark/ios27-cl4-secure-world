#!/usr/bin/env python3
"""Fast: raw-scan __TEXT_EXEC for `movz Xd,#imm` (any Rd) encoding a PAC
discriminator, then decode a small window to classify the paired sign/call.
Usage: disc_fast.py [disc_hex]"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM
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
def f2v(f):
    for n,vm,vs,fo,fs in SEGS:
        if fo<=f<fo+fs: return vm+(f-fo)
    return None
disc=int(sys.argv[1],0) if len(sys.argv)>1 else 0xba5
te=[s for s in SEGS if s[0]=="__TEXT_EXEC"][0]
lo_fo=te[3]; hi_fo=te[3]+te[4]
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
# movz Xd,#imm16, hw=0 : 0xD2800000 | (imm16<<5) | Rd ; also `mov` alias same enc
base = 0xD2800000 | ((disc & 0xffff)<<5)
hits=[]
f=lo_fo
while f < hi_fo:
    w=struct.unpack("<I",D[f:f+4])[0]
    if (w & 0xFFFFFFE0) == base:  # mask Rd
        hits.append(f)
    f+=4
print(f"# {len(hits)} movz #{disc:#x} raw hits", file=sys.stderr)
def classify(f):
    va=f2v(f)
    win=D[f:f+8*4]
    ins=list(md.disasm(win,va))
    if not ins: return None
    reg=ins[0].operands[0].reg
    for n2 in ins[1:]:
        mm=n2.mnemonic
        if mm.startswith("paci") or mm.startswith("pacd"):
            return ("SIGN",n2)
        if mm in("blraa","braa","blrab","brab"):
            return ("CALL",n2)
        if mm.startswith("auti") or mm.startswith("autd"):
            return ("AUTH",n2)
    return ("?",ins[0])
from collections import Counter
c=Counter()
for f in hits:
    r=classify(f)
    if not r: continue
    kind,n2=r
    c[kind]+=1
    if kind in("SIGN","AUTH"):
        print(f"{f2v(f):#011x} fo={f:#09x} [{kind}] {n2.mnemonic:7} {n2.op_str}")
print("# kinds:",dict(c), file=sys.stderr)
