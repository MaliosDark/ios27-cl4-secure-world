#!/bin/bash
# Boot iOS 27 from the full root filesystem instead of the restore ramdisk.
#
# darwin-vm has no storage device at all, so the only way to present a root
# filesystem is to load it as the ramdisk and point the kernel at md0. That
# means the whole image is copied into guest RAM, hence the large -m.
#
# Everything for the display stack is enabled here: the real interrupt
# controller, the DARTs, the emulated DCP (DARWIN_RTKIT) and the lit panel with
# interactive keyboard (DARWIN_FB). Put a decrypted rootfs .dmg (>1G) in ./rootfs/
# or set ROOTFS=. A QEMU window opens showing the iPhone panel; type into it.
set -euo pipefail

DVM="$(cd "$(dirname "$0")" && pwd)"
FW="$DVM/firmware"
Q="$DVM/qemu-sptm/build/qemu-system-aarch64"

ROOTFS="${ROOTFS:-}"
if [[ -z "$ROOTFS" ]]; then
    ROOTFS=$(find "$DVM/rootfs" -name '*.dmg' -size +1G 2>/dev/null | head -1)
fi
[[ -n "$ROOTFS" && -f "$ROOTFS" ]] || { echo "no root filesystem image found; set ROOTFS=" >&2; exit 1; }

MEM="${MEM:-20G}"   # dtree_ios declares dram-size=20GB (the rootfs does not fit in 8GB)
echo "rootfs : $ROOTFS ($(du -h "$ROOTFS" | cut -f1))"
echo "memory : $MEM"

fix_tty() { stty sane 2>/dev/null || true; }
trap fix_tty EXIT

DARWIN_AIC=1 DARWIN_DART=1 DARWIN_DISP=all DARWIN_RTKIT=1 DARWIN_FB=1 \
"$Q" -M darwin \
    -bootkc  "${BOOTKC:-$FW/bootkc.md0}" \
    -dtree   "${DTREE:-$FW/dtree_ios}" \
    -tc      "$FW/ramdisk.tc" \
    -ramdisk "$ROOTFS" \
    -sptm    "$FW/sptm" \
    -txm     "$FW/txm" \
    -args    "rd=md0 serial=3 -v wdt=-1 wlan-olyhal-abort" \
    -m "$MEM" \
    -serial mon:stdio \
    "$@"
