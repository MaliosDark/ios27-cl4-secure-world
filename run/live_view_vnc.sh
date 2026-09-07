#!/bin/bash
# Runs the VM serving the screen over VNC on localhost:5900, so you can
# WATCH IT LIVE from another app (macOS Screen Sharing).
# While it runs: open Finder -> Go -> Connect to Server (Cmd+K) ->
#   vnc://localhost:5900     (or open "Screen Sharing" and enter localhost)
set -euo pipefail
cd "$(dirname "$0")"
D=firmware; DT=$D/dtree; [[ -f $D/dtree_dbg ]] && DT=$D/dtree_dbg
echo ">> Live screen over VNC: connect to  vnc://localhost:5900"
DARWIN_RTKIT=1 DARWIN_FB=1 \
qemu-sptm/build/qemu-system-aarch64 -M darwin \
  -bootkc $D/bootkc -dtree $DT -tc $D/ramdisk.tc -ramdisk $D/ramdisk.dmg \
  -sptm $D/sptm -txm $D/txm \
  -args "rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort" \
  -vnc 127.0.0.1:0 -serial mon:stdio -m 8G "$@"
