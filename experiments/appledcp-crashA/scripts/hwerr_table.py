#!/usr/bin/env python3
"""hwerr_table.py -- dump the base-XNU hardware-error (hwerr) decoder table that
crash A overruns. Resolves the chained-fixup {string_key, decode_fn@disc0xba5,
handler_fn@disc0x3b24} entries and shows where the valid table ends and the
adjacent const string-pointer pool begins (the region the walk falls into).

Table base defaults to 0xfffffff007de2338 (the "DPC" / s3_5_c15_c0_5 group,
the one crash A overruns; static vmaddr, __DATA_CONST). Usage:
  hwerr_table.py [table_vmaddr] [nrows]
"""
import sys, struct
KC="/Users/maliosdark/darwin-vm/firmware/bootkc"; D=open(KC,"rb").read()
SEGS=[]; ncmds,=struct.unpack("<I",D[16:20]); off=32
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",D[off:off+8])
    if cmd==0x19:
        n=D[off+8:off+24].split(b"\0")[0].decode()
        vm,vs,fo,fs=struct.unpack("<QQQQ",D[off+24:off+56]); SEGS.append((n,vm,vs,fo,fs))
    off+=cs
IMG=min(s[1] for s in SEGS)
def v2f(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs and v-vm<fs: return fo+(v-vm)
def seg(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs: return n
    return "?"
def rdstr(v):
    f=v2f(v)
    if f is None: return None
    e=D.find(b"\0",f); return D[f:e].decode('latin1')
def res(raw): return IMG+(raw & 0x3FFFFFFF)      # DYLD_CHAINED_PTR_64_KERNEL_CACHE
def isauth(raw): return (raw>>63)&1
def disc(raw): return (raw>>32)&0xffff
tbl=int(sys.argv[1],0) if len(sys.argv)>1 else 0xfffffff007de2338
n  =int(sys.argv[2],0) if len(sys.argv)>2 else 11
f=v2f(tbl)
print(f"# hwerr decoder table @ {tbl:#x} ({seg(tbl)}), stride 0x18, {{key@0, cb@8, cb2@0x10}}")
print(f"# dispatcher 0xfffffff00ac9376c: cb=[x2+8] called `blraa x8,#0xba5`; walk stops on cb==0")
valid=0
for i in range(n):
    row=D[f+i*0x18:f+i*0x18+0x18]
    a,b,c=struct.unpack("<QQQ",row)
    ks=rdstr(res(a))
    tag = "hwerr entry" if (isauth(b) and disc(b)==0xba5) else ">>> STRING POOL (overrun) <<<"
    if isauth(b) and disc(b)==0xba5: valid+=1
    print(f"+{i*0x18:#05x} key={res(a):#x} {str(ks)[:34]:34} cb={res(b):#x} auth={isauth(b)} disc={disc(b):#06x}  {tag}")
print(f"# valid hwerr_type entries: {valid}; crash A `blraa`s the first STRING-POOL cb (\" (bad cmd)\" = 0xfffffff00706e459)")
