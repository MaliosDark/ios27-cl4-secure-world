#!/usr/bin/env python3
"""Symbolicate static vmaddrs against the kernelcache LC_SYMTAB (nlist_64).
Usage: sym.py <vmaddr> [more...]   |   sym.py grep <substr>   |   sym.py name <symname>"""
import sys, struct, bisect
KC="/Users/maliosdark/darwin-vm/firmware/bootkc"; D=open(KC,"rb").read()
ncmds,=struct.unpack("<I",D[16:20]); off=32; symoff=stroff=nsyms=0
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",D[off:off+8])
    if cmd==0x2:  # LC_SYMTAB
        symoff,nsyms,stroff,strsize=struct.unpack("<IIII",D[off+8:off+24])
    off+=cs
SYMS=[]  # (value,name)
for i in range(nsyms):
    o=symoff+i*16
    n_strx,n_type,n_sect,n_desc,n_value=struct.unpack("<IBBHQ",D[o:o+16])
    if n_value==0: continue
    if n_type & 0x0e == 0x0e or True:  # include all defined
        name=D[stroff+n_strx:D.find(b"\0",stroff+n_strx)].decode('latin1')
        SYMS.append((n_value,name))
SYMS.sort()
VALS=[v for v,_ in SYMS]
def nearest(v):
    i=bisect.bisect_right(VALS,v)-1
    if i<0: return None
    return SYMS[i][0],SYMS[i][1],v-SYMS[i][0]
if __name__=="__main__":
    if sys.argv[1]=="grep":
        s=sys.argv[2].lower()
        for v,n in SYMS:
            if s in n.lower(): print(f"{v:#x} {n}")
    elif sys.argv[1]=="name":
        for v,n in SYMS:
            if n==sys.argv[2]: print(f"{v:#x} {n}")
    else:
        for a in sys.argv[1:]:
            v=int(a,0); r=nearest(v)
            if r: print(f"{v:#x} = {r[1]} + {r[2]:#x}")
            else: print(f"{v:#x} = ?")
