"""Generate trust-cache cdhashes for every on-disk Mach-O in a mounted rootfs.

darwin-vm boots iOS 27 with an ad-hoc-signed userland. AMFI will only run an
ad-hoc binary (flags 0x2) whose cdhash is present in a loaded trust cache;
otherwise the process is CS_KILLED. launchd (com.apple.xpc.launchd) is ad-hoc,
so if its cdhash is missing the kernel panics "CS_KILLED initproc failed to
start". The same applies to every daemon launchd spawns.

This walks a mounted rootfs, finds Mach-O files by magic, extracts each one's
canonical cdhash via `codesign -dvvv`, and merges the 40-hex-char (20-byte)
cdhashes into an all_hashes list (deduped, sorted) that build_tc.py turns into a
trust cache. Binaries whose code lives in the dyld shared cache are validated by
the cache signature and need no entry here; this covers the standalone
executables loaded from disk.

This is legitimate trust-cache construction (the same cdhash list a real iOS
static trust cache carries), not a signature bypass.

Usage:
    python3 -m scripts.patchers.darwinvm_gen_rootfs_trustcache \\
        <rootfs_mount> <existing_all_hashes> <out_all_hashes> [--jobs N]

Then rebuild the trust cache:
    python3 build_tc.py <out_all_hashes> firmware/ramdisk.tc
"""

import os
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

MACHO_MAGICS = {
    0xFEEDFACF,  # MH_MAGIC_64
    0xCFFAEDFE,  # MH_CIGAM_64 (swapped)
    0xFEEDFACE,  # MH_MAGIC (32)
    0xCEFAEDFE,  # MH_CIGAM (32)
    0xCAFEBABE,  # FAT_MAGIC
    0xBEBAFECA,  # FAT_CIGAM
}


def is_macho(path):
    try:
        with open(path, "rb") as f:
            magic = struct.unpack(">I", f.read(4))[0]
        return magic in MACHO_MAGICS or struct.unpack("<I", struct.pack(">I", magic))[0] in MACHO_MAGICS
    except Exception:
        return False


def cdhash_of(path):
    """Return the canonical cdhash (40 hex chars) of a Mach-O, or None."""
    try:
        out = subprocess.run(
            ["codesign", "-dvvv", path],
            capture_output=True, text=True, timeout=30,
        ).stderr
    except Exception:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("CDHash="):
            h = line.split("=", 1)[1].strip().lower()
            if len(h) == 40 and all(c in "0123456789abcdef" for c in h):
                return h
    return None


def walk_machos(root):
    """Yield paths of Mach-O files under root (skips the dyld cache dir)."""
    skip_dirs = {"com.apple.dyld"}  # cache chunks: validated as a whole, not per-file
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                continue
            try:
                if os.path.getsize(p) < 4:
                    continue
            except OSError:
                continue
            if is_macho(p):
                yield p


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    jobs = 8
    for a in sys.argv[1:]:
        if a.startswith("--jobs"):
            jobs = int(a.split("=")[1]) if "=" in a else 8
    if len(args) < 3:
        print(f"Usage: {sys.argv[0]} <rootfs_mount> <existing_all_hashes> <out_all_hashes> [--jobs=N]")
        sys.exit(1)

    rootfs, existing, out = args[0], args[1], args[2]

    have = set()
    if os.path.isfile(existing):
        with open(existing) as f:
            for line in f:
                h = line.strip().lower()
                if len(h) == 40:
                    have.add(h)
    print(f"[tc-gen] existing cdhashes: {len(have)}")

    print(f"[tc-gen] scanning {rootfs} for Mach-O files ...")
    machos = list(walk_machos(rootfs))
    print(f"[tc-gen] found {len(machos)} Mach-O files; extracting cdhashes ({jobs} workers) ...")

    found = set()
    done = 0
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for h in ex.map(cdhash_of, machos):
            done += 1
            if done % 500 == 0:
                print(f"[tc-gen]   {done}/{len(machos)} scanned, {len(found)} cdhashes")
            if h:
                found.add(h)

    new = found - have
    print(f"[tc-gen] extracted {len(found)} cdhashes; {len(new)} are new")

    merged = sorted(have | found)
    with open(out, "w") as f:
        f.write("\n".join(merged) + "\n")
    print(f"[tc-gen] wrote {len(merged)} cdhashes -> {out}")
    print(f"[tc-gen] next: python3 build_tc.py {out} firmware/ramdisk.tc")


if __name__ == "__main__":
    main()
