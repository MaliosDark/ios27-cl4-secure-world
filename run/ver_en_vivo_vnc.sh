#!/bin/bash
# Corre la VM sirviendo la pantalla por VNC en localhost:5900, para poder
# VERLA EN VIVO desde otra app (Compartir Pantalla de macOS).
# Mientras corre: abrí Finder -> Ir -> Conectarse al servidor (Cmd+K) ->
#   vnc://localhost:5900     (o abrí "Compartir Pantalla" y poné localhost)
set -euo pipefail
cd "$(dirname "$0")"
D=firmware; DT=$D/dtree; [[ -f $D/dtree_dbg ]] && DT=$D/dtree_dbg
echo ">> Pantalla en vivo por VNC: conectate a  vnc://localhost:5900"
DARWIN_RTKIT=1 DARWIN_FB=1 \
qemu-sptm/build/qemu-system-aarch64 -M darwin \
  -bootkc $D/bootkc -dtree $DT -tc $D/ramdisk.tc -ramdisk $D/ramdisk.dmg \
  -sptm $D/sptm -txm $D/txm \
  -args "rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort" \
  -vnc 127.0.0.1:0 -serial mon:stdio -m 8G "$@"
