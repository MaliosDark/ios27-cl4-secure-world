#!/usr/bin/env python3
"""Neutralise RTBuddy::start()'s "route not found -> abort" check.

RTBuddy iterates its routes; when one resolves to NULL (which happens for the
DCP because its route leads to a secure-world service that does not exist in
this VM) it branches to an error path that fails start(). This turns that one
conditional branch into a NOP so the loop continues, letting start() complete.

Anchored semantically, not by raw offset: the target CBZ is located by walking
RTBuddy's fileset __TEXT_EXEC and confirmed by the surrounding "Finding route"
(#0x3f4) / "Success route" (#0x412) string-load instructions, which are unique
to this function. The replacement NOP is produced by Keystone.
"""
import struct, sys, argparse
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

LC_SEGMENT_64   = 0x19
LC_FILESET_ENTRY= 0x80000035

def macho_cmds(d, off):
    ncmds = struct.unpack('<I', d[off+16:off+20])[0]
    p = off + 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack('<II', d[p:p+8])
        yield p, cmd, cs
        p += cs

def fileset_fileoff(d, name):
    for p, cmd, cs in macho_cmds(d, 0):
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff = struct.unpack('<QQ', d[p+8:p+24])
            nm = d[p+32:d.find(b'\0', p+32)]
            if nm == name:
                return fileoff
    return None

def text_exec(d, fo):
    for p, cmd, cs in macho_cmds(d, fo):
        if cmd == LC_SEGMENT_64:
            segname = d[p+8:p+24].rstrip(b'\0')
            vmaddr, vmsize, foff, fsz = struct.unpack('<QQQQ', d[p+24:p+56])
            if segname == b'__TEXT_EXEC':
                return vmaddr, foff
    return None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bootkc')
    ap.add_argument('-n', '--dry-run', action='store_true')
    args = ap.parse_args()

    d = bytearray(open(args.bootkc, 'rb').read())

    fo = fileset_fileoff(d, b'com.apple.driver.RTBuddy')
    if fo is None:
        sys.exit("RTBuddy fileset not found")
    tx_va, tx_fo = text_exec(d, fo)
    if tx_va is None:
        sys.exit("RTBuddy __TEXT_EXEC not found")

    def at(va):  # VA -> file offset
        return tx_fo + (va - tx_va)

    # Semantic anchors: the two logging calls unique to the route loop.
    FIND_VA = 0xFFFFFFF00A7C5200   # add x3, x3, #0x3f4  -> "Finding route %d"
    SUCC_VA = 0xFFFFFFF00A7C538C   # add x3, x3, #0x412  -> "Success route %d"
    CBZ_VA  = 0xFFFFFFF00A7C52F0   # cbz x0, <error>     -> the check to remove

    if d[at(FIND_VA):at(FIND_VA)+4] != bytes([0x63,0xd0,0x0f,0x91]):
        sys.exit("anchor mismatch: 'Finding route' add not where expected")
    if d[at(SUCC_VA):at(SUCC_VA)+4] != bytes([0x63,0x48,0x10,0x91]):
        sys.exit("anchor mismatch: 'Success route' add not where expected")

    cbz_fo = at(CBZ_VA)
    cur = bytes(d[cbz_fo:cbz_fo+4])
    # CBZ Xt, label : top byte 0xB4, and it must be a cbz of x0 (Rt=0)
    if not (cur[3] == 0xb4 and (cur[0] & 0x1f) == 0x00):
        sys.exit(f"target is not 'cbz x0, ...': {cur.hex()}")

    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    nop, _ = ks.asm("nop")
    nop = bytes(nop)
    print(f"RTBuddy route check at file 0x{cbz_fo:X}: {cur.hex()} -> {nop.hex()} (nop)")

    if not args.dry_run:
        d[cbz_fo:cbz_fo+4] = nop
        open(args.bootkc, 'wb').write(d)
        print("patched")
    else:
        print("dry run, not written")

if __name__ == '__main__':
    main()
