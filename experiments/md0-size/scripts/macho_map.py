#!/usr/bin/env python3
"""Parse a Mach-O FILESET kernelcache: list all segments (top-level + each
LC_FILESET_ENTRY kext inner segments) with vmaddr, fileoff, size.
Provides vmaddr<->fileoffset mapping across ALL exec segments."""
import struct, sys

KC = "/Users/maliosdark/darwin-vm/firmware/bootkc"

LC_SEGMENT_64      = 0x19
LC_FILESET_ENTRY   = 0x80000035
LC_SYMTAB          = 0x2

class Seg:
    __slots__=("name","vmaddr","vmsize","fileoff","filesize","owner","initprot")
    def __init__(s,name,vmaddr,vmsize,fileoff,filesize,owner,initprot):
        s.name=name; s.vmaddr=vmaddr; s.vmsize=vmsize; s.fileoff=fileoff
        s.filesize=filesize; s.owner=owner; s.initprot=initprot
    def __repr__(s):
        return f"{s.owner:32s} {s.name:16s} vm={s.vmaddr:#018x} sz={s.vmsize:#010x} fo={s.fileoff:#010x} fsz={s.filesize:#010x} prot={s.initprot:#x}"

def parse_header(data, base_off, owner):
    """Parse one mach header at base_off, return list of Seg."""
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<IiiIIIII", data, base_off)
    segs=[]
    entries=[]  # (name, fileoff-of-entry-header)
    off = base_off + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            segname = data[off+8:off+24].split(b'\0')[0].decode('latin1')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
            maxprot, initprot, nsects, segflags = struct.unpack_from("<IIII", data, off+56)
            segs.append(Seg(segname, vmaddr, vmsize, fileoff, filesize, owner, initprot))
        elif cmd == LC_FILESET_ENTRY:
            e_vmaddr, e_fileoff = struct.unpack_from("<QQ", data, off+8)
            entryid_off = struct.unpack_from("<I", data, off+24)[0]
            name = data[off+entryid_off:off+cmdsize].split(b'\0')[0].decode('latin1')
            entries.append((name, e_fileoff))
        off += cmdsize
    return segs, entries

def load():
    data = open(KC,"rb").read()
    top_segs, entries = parse_header(data, 0, "<TOP>")
    all_segs = list(top_segs)
    for name, efo in entries:
        segs, _ = parse_header(data, efo, name)
        all_segs.extend(segs)
    return data, all_segs, entries

def build_maps(all_segs):
    # only segments with file backing and nonzero filesize participate in v<->f
    execmap=[]  # (vmaddr, vmaddr+vmsize, fileoff)
    for s in all_segs:
        if s.filesize>0:
            execmap.append(s)
    return execmap

def v2f(all_segs, va):
    for s in all_segs:
        if s.filesize>0 and s.vmaddr <= va < s.vmaddr + s.filesize:
            return s.fileoff + (va - s.vmaddr), s
    return None, None

def f2v(all_segs, fo):
    for s in all_segs:
        if s.filesize>0 and s.fileoff <= fo < s.fileoff + s.filesize:
            return s.vmaddr + (fo - s.fileoff), s
    return None, None

if __name__=="__main__":
    data, all_segs, entries = load()
    print(f"# {len(entries)} fileset entries, {len(all_segs)} total segments")
    print("# TOP-LEVEL + EXEC segments (initprot has x bit 0x4):")
    for s in all_segs:
        if s.owner=="<TOP>" or (s.initprot & 0x4):
            print(s)
    # sanity: map the known "ramdisk params" fileoff
    va, s = f2v(all_segs, 0xc6463)
    print(f"\n# fileoff 0xc6463 -> vmaddr {va:#x} in {s.owner}/{s.name}" if va else "# 0xc6463 unmapped")
