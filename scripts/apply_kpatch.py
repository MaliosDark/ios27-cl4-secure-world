#!/usr/bin/env python3
# apply_kpatch.py SRC DST off:hexbytes [off:hexbytes ...]
import sys, shutil
src, dst = sys.argv[1], sys.argv[2]
shutil.copyfile(src, dst)
data = bytearray(open(dst,'rb').read())
for spec in sys.argv[3:]:
    off, hx = spec.split(':')
    off = int(off,16); b = bytes.fromhex(hx)
    print(f"@ {hex(off)}: {data[off:off+len(b)].hex()} -> {hx}")
    data[off:off+len(b)] = b
open(dst,'wb').write(bytes(data))
print(f"wrote {dst} ({len(data)} bytes)")
