#!/usr/bin/env python3
import sys, re
sys.path.insert(0,"/Users/maliosdark/ios27-cl4-secure-world/experiments/md0-size/scripts")
from macho_map import load, f2v

data, all_segs, entries = load()

anchors = [b"RAMDisk", b"ramdisk params @%s:%d", b"mdevadd", b"memdev.c",
           b"md%d", b"-rootdmg-ramdisk", b"imageboot_mount_ramdisk",
           b"IOHibernateState", b"rootdmg", b"mdevlookup", b"mdevremove",
           b"container size %llu", b"greater than device size"]

for a in anchors:
    start=0
    hits=[]
    while True:
        i = data.find(a, start)
        if i<0: break
        # require NUL-terminated cstring-ish (preceding is NUL or printable-start)
        hits.append(i)
        start=i+1
        if len(hits)>12: break
    print(f"=== {a!r}  ({len(hits)} hits)")
    for i in hits:
        va, s = f2v(all_segs, i)
        ctx = data[i:i+40].split(b'\0')[0]
        tag = f"{s.owner}/{s.name}" if s else "??"
        print(f"    fo={i:#x} va={va:#x} [{tag}]  {ctx!r}")
