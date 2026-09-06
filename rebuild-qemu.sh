#!/bin/bash
# Apply the CL4 secure-world patches onto a fresh qemu-sptm checkout and build.
# Usage: ./rebuild-qemu.sh /path/to/darwin-vm/qemu-sptm
set -euo pipefail
QSPTM="${1:?usage: rebuild-qemu.sh /path/to/qemu-sptm}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$QSPTM"
echo "[*] base HEAD: $(git rev-parse HEAD)"
git apply --3way "$HERE/qemu-patches/qemu-sptm-cl4-all.patch"
[ -d build ] || (mkdir build && cd build && ../configure --target-list=aarch64-softmmu --disable-werror)
cd build && make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
echo "[*] built: $QSPTM/build/qemu-system-aarch64"
