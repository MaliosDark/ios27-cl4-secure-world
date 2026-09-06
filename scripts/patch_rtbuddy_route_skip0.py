#!/usr/bin/env python3
"""Start RTBuddy's route loop at index 1, skipping the secure route (route 0).

Experiment result (FINDINGS Part 39): this converts the fatal
panic("Unabled to attach route: 0") into a CLEAN failure -- iOS 27 boots to a
root shell with no panic -- but RTBuddy(DCP) still ends !registered. So the
secure route is mandatory for *registration*, not merely to avoid the panic:
start() returns without registering when route 0 is skipped. Kept as a
documented experiment; not part of the shipped patch set.

Route index x24 starts at 0 (mov x24,#0 @0xa7c518c) with byte offset x22 at 0
(mov x22,#0 @0xa7c5188). Setting them to 1 and 4 skips iteration 0 (the secure
DCP-EXCLAVE route). Anchored inside the route loop (Finding/Success string
adds); bytes verified before writing.
"""
import struct, sys, argparse
LC_SEG=0x19; LC_FSE=0x80000035
def cmds(d,off):
    n=struct.unpack('<I',d[off+16:off+20])[0]; p=off+32
    for _ in range(n):
        c,cs=struct.unpack('<II',d[p:p+8]); yield p,c,cs; p+=cs
def fs(d,name):
    for p,c,cs in cmds(d,0):
        if c==LC_FSE:
            va,fo=struct.unpack('<QQ',d[p+8:p+24])
            if d[p+32:d.find(b'\0',p+32)]==name: return fo
def tx(d,fo):
    for p,c,cs in cmds(d,fo):
        if c==LC_SEG and d[p+8:p+24].rstrip(b'\0')==b'__TEXT_EXEC':
            va,vs,f,fz=struct.unpack('<QQQQ',d[p+24:p+56]); return va,f
    return None,None
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('bootkc'); ap.add_argument('-n','--dry-run',action='store_true')
    a=ap.parse_args(); d=bytearray(open(a.bootkc,'rb').read())
    fo=fs(d,b'com.apple.driver.RTBuddy'); tva,tfo=tx(d,fo); at=lambda v:tfo+(v-tva)
    # anchors: Finding/Success adds
    if d[at(0xFFFFFFF00A7C5200):at(0xFFFFFFF00A7C5200)+4]!=bytes([0x63,0xd0,0x0f,0x91]): sys.exit("anchor Finding")
    if d[at(0xFFFFFFF00A7C538C):at(0xFFFFFFF00A7C538C)+4]!=bytes([0x63,0x48,0x10,0x91]): sys.exit("anchor Success")
    o1=at(0xFFFFFFF00A7C5188); o2=at(0xFFFFFFF00A7C518C)
    if bytes(d[o1:o1+4])!=bytes([0x16,0,0x80,0xd2]) or bytes(d[o2:o2+4])!=bytes([0x18,0,0x80,0xd2]):
        sys.exit("anchor mismatch: expected mov x22,#0 / mov x24,#0")
    print(f"route loop start index 0->1 @0x{o1:x},0x{o2:x}")
    if not a.dry_run:
        d[o1:o1+4]=bytes([0x96,0,0x80,0xd2]); d[o2:o2+4]=bytes([0x38,0,0x80,0xd2])
        open(a.bootkc,'wb').write(d); print("patched")
    else: print("dry run")
if __name__=='__main__': main()
