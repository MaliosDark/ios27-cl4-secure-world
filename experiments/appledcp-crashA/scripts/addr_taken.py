#!/usr/bin/env python3
"""Raw-scan __TEXT_EXEC for adrp/add pairs that materialize a target static
vmaddr (address-taken). Also scans __DATA_CONST/__DATA for the target encoded
as a chained-fixup pointer (low 36 bits == target static offset).
Usage: addr_taken.py <target_static_vmaddr>"""
import sys,struct
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
def seg(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs: return n
    return "?"
target=int(sys.argv[1],0)
tpage=target & ~0xfff
tlow=target & 0xfff
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
# 1) adrp+add materialization in __TEXT_EXEC (raw scan for add #tlow, verify adrp)
te=[s for s in SEGS if s[0]=="__TEXT_EXEC"][0]
lo_fo=te[3]; hi_fo=te[3]+te[4]
addbase = 0x91000000 | ((tlow & 0xfff)<<10)
print(f"# scanning adrp+add -> {target:#x} (page {tpage:#x} low {tlow:#x})")
f=lo_fo
while f<hi_fo:
    w=struct.unpack("<I",D[f:f+4])[0]
    if (w & 0xFFC00000)==0x91000000 and ((w>>10)&0xfff)==tlow:
        # this is add xd,xn,#tlow ; find matching adrp for xn in prev 8 insns
        rn=(w>>5)&0x1f
        va=f2v(f)
        # decode backwards window
        win=D[max(lo_fo,f-8*4):f+4]; start=f2v(max(lo_fo,f-8*4))
        adrp_pg=None
        for ins in md.disasm(win,start):
            if ins.mnemonic=="adrp" and ins.operands[0].reg is not None:
                # record page for that reg
                if ins.operands[0].type==ARM64_OP_REG:
                    pass
            if ins.address==va: break
            if ins.mnemonic=="adrp":
                # crude: track reg->page
                pass
        # simpler: decode the add itself + look 5 back for adrp same-reg page tpage
        w2=D[max(lo_fo,f-6*4):f+4]
        ins2=list(md.disasm(w2,f2v(max(lo_fo,f-6*4))))
        pg={}
        for ins in ins2:
            if ins.mnemonic=="adrp":
                pg[ins.operands[0].reg]=ins.operands[1].imm
            if ins.address==va:
                rnreg=ins.operands[1].reg
                if pg.get(rnreg)==tpage:
                    print(f"ADRP+ADD  {va:#011x} fo={f:#09x}  [{seg(va)}]")
                break
    f+=4
# 2) chained-fixup pointer in DATA segments: raw 8-byte where low bits == target
# arm64e kernel fixups: rebase target stored as (target - some_base) in low 36 bits.
# Just search for any 8-byte little value whose (val & 0xffffffff) == target&0xffffffff
tgt32=target & 0xffffffff
for n,vm,vs,fo,fs in SEGS:
    if not n.startswith("__DATA"): continue
    b=D[fo:fo+fs]
    for i in range(0,len(b)-8,8):
        val=struct.unpack("<Q",b[i:i+8])[0]
        if (val & 0xffffffff)==tgt32 and (val>>32)!=0xffffffff:
            print(f"DATAPTR   {f2v(fo+i):#011x} fo={fo+i:#09x} raw={val:#018x} [{n}]")
