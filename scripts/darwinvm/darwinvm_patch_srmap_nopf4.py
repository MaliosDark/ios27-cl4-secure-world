#!/usr/bin/env python3
"""DVM Wall #2 fix: NOP the over-rejecting map-info check in
vm_shared_region_map_and_slide_setup so the dyld shared cache maps.

At static VA 0xfffffff00b0bd11c the kernel does:
    ldr w8, [sp, #0xf4]        ; map-info struct+0x44 (a benign 0x63 property in-VM)
    cbnz w8, 0xb0bd8a8         ; -> kr=1 path, cache map fails
NOP the cbnz. The map itself succeeds; this only skips a post-map property rejection that
over-fires in the SEP-less VM. After this, launchd maps the cache and runs full userspace.

Usage: darwinvm_patch_srmap_nopf4.py <bootkc_in> <bootkc_out>
Derivation is anchored to the exact cbnz encoding at the known VA; it verifies before writing.
"""
import sys, struct

KBASE = 0xfffffff007004000
VA    = 0xfffffff00b0bd11c   # cbnz w8, 0xb0bd8a8  (map-info reject in map_and_slide_setup)
NOP   = 0xd503201f

def main():
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(2)
    d = bytearray(open(sys.argv[1], "rb").read())
    off = VA - KBASE
    cur = struct.unpack_from("<I", d, off)[0]
    # CBNZ (32-bit): opcode byte 0x35, Rt in low 5 bits (expect w8)
    if (cur >> 24) != 0x35 or (cur & 0x1f) != 8:
        print("ERROR: insn @%#x = %#010x is not 'cbnz w8'; wrong kernel/offset" % (VA, cur))
        sys.exit(1)
    tgt = VA + (((cur >> 5) & 0x7ffff) * 4)
    if tgt != 0xfffffff00b0bd8a8:
        print("ERROR: cbnz target %#x != expected 0xb0bd8a8" % tgt); sys.exit(1)
    struct.pack_into("<I", d, off, NOP)
    open(sys.argv[2], "wb").write(bytes(d))
    print("OK: NOP'd cbnz @%#x (was -> %#x) in %s" % (VA, tgt, sys.argv[2]))

if __name__ == "__main__":
    main()
