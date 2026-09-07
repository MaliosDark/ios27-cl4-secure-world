#!/bin/bash
# Opens the QEMU window and shows the iPhone screen (DCP panel)
# booting iOS 27 live. Run this on your Mac (NOT headless).
set -euo pipefail
cd "$(dirname "$0")"
D=firmware
DT=$D/dtree; [[ -f $D/dtree_dbg ]] && DT=$D/dtree_dbg
DARWIN_RTKIT=1 DARWIN_FB=1 \
qemu-sptm/build/qemu-system-aarch64 \
  -M darwin \
  -bootkc  $D/bootkc \
  -dtree   $DT \
  -tc      $D/ramdisk.tc \
  -ramdisk $D/ramdisk.dmg \
  -sptm    $D/sptm \
  -txm     $D/txm \
  -args    "rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort" \
  -serial  mon:stdio \
  -m 8G
# ^ without "-display none": QEMU opens a WINDOW with the iPhone panel (640x1136).
#   The serial log prints in this same terminal.
