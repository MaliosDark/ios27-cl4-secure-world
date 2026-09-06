#!/bin/bash
# Abre la ventana de QEMU y muestra la pantalla del iPhone (panel del DCP)
# booteando iOS 27 en vivo. Corré esto en tu Mac (NO headless).
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
# ^ sin "-display none": QEMU abre una VENTANA con el panel del iPhone (640x1136).
#   El log serial sale en esta misma terminal.
