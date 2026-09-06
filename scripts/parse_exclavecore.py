#!/usr/bin/env python3
"""Parse the Apple exclavecore DNUB bundle and extract its components.

The exclavecore_bundle.<chip>.RELEASE.im4p payload is a 'DNUB' container: a
24-byte header, then a table of 24-byte TOC entries (4-char tag, u64 offset,
u64 size, u32 type), then the component blobs. It holds the secure-world
kernel ('knl'), trusted app domains ('tad'), code text ('txt'), and the
exclave trustcache ('tsr') that SPTM launches as the SK domain.

Usage: parse_exclavecore.py <exclavecore-payload> [-x <outdir>]
"""
import struct, sys, argparse, os

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bundle')
    ap.add_argument('-x', '--extract', metavar='DIR')
    a = ap.parse_args()
    d = open(a.bundle, 'rb').read()

    if d[8:12] != b'DNUB':
        sys.exit(f"not a DNUB bundle (magic={d[8:12]!r})")

    n = struct.unpack('<I', d[0x14:0x18])[0]   # entry count
    print(f"DNUB bundle: {len(d)} bytes, {n} components\n")
    print(f"  {'tag':<6}{'offset':>12}{'size':>12}{'type':>6}  {'kind'}")

    toc = 0x284   # first TOC entry (empirically after the fixed header)
    comps = []
    for i in range(n):
        off = toc + i*24
        tag = d[off:off+4].decode('latin1')
        o, s = struct.unpack('<QQ', d[off+4:off+20])
        t = struct.unpack('<I', d[off+20:off+24])[0]
        kind = {'txt':'code text','tad':'trusted-app domain','knl':'SECURE KERNEL',
                'tsr':'exclave trustcache','ldb':'loadable'}.get(tag[:3], '?')
        ismacho = s and o+4 <= len(d) and d[o:o+4] == b'\xcf\xfa\xed\xfe'
        print(f"  {tag:<6}{o:>12x}{s:>12x}{t:>6x}  {kind}{' [Mach-O]' if ismacho else ''}")
        if s:
            comps.append((tag, o, s))

    if a.extract:
        os.makedirs(a.extract, exist_ok=True)
        for tag, o, s in comps:
            p = os.path.join(a.extract, tag)
            open(p, 'wb').write(d[o:o+s])
        print(f"\nextracted {len(comps)} components to {a.extract}/")

if __name__ == '__main__':
    main()
