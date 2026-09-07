#!/bin/zsh
# inject_cryptex.sh - decrypts (if needed) the Cryptex1,SystemOS and builds an
# iOS 27 rootfs that CONTAINS IT in /private/preboot/Cryptexes/OS, so that
# /sbin/launchd finds the dyld_shared_cache and libSystem.B.dylib.
#
# The original rootfs is a "tight" APFS volume (no free space), so it CANNOT
# be converted to UDRW and grown: a new 20GB APFS image is created and
# the rootfs + the cryptex are copied into it. (Without sudo: the files end up owned
# by your uid but world-readable; root in the guest maps the cache anyway.)
#
# USAGE:  ./inject_cryptex.sh <cryptex 094-13150-145.dmg.aea | .dmg>
# OUTPUT: firmware/rootfs_with_cryptex.dmg   ->   ROOTFS=... ./run_rootfs.sh
set -euo pipefail
HERE=${0:a:h}; cd "$HERE"
IN=${1:?path to Cryptex1,SystemOS (.dmg.aea or .dmg)}
SRC=rootfs/24A5430a__iPhone17,3/decrypted/094-13182-141.dmg
OUT=firmware/rootfs_with_cryptex.dmg
WORK=cryptex/work; mkdir -p "$WORK"

CX="$IN"
if [[ "$IN" == *.aea ]]; then
  echo "[*] decrypting cryptex AEA (ipsw fetches Apple's fcs-key; does not print keys)..."
  ipsw fw aea -o "$WORK" "$IN"
  CX=$(find "$WORK" -maxdepth 1 -name '*.dmg' -size +1G | head -1)
fi
[[ -f "$CX" ]] || { echo "no cryptex dmg"; exit 1; }
echo "[*] cryptex: $CX"

rm -f "$OUT"
echo "[*] creating 20GB APFS image ..."
hdiutil create -size 20g -fs APFS -volname iOSRoot -layout GPTSPUD -type UDIF "$OUT" >/dev/null
N=$(mktemp -d /tmp/new.XXXX); S=$(mktemp -d /tmp/src.XXXX); C=$(mktemp -d /tmp/cxs.XXXX)
cleanup(){ for m in "$N" "$S" "$C"; do hdiutil detach "$m" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
hdiutil attach "$OUT" -nobrowse -mountpoint "$N" >/dev/null
hdiutil attach "$SRC" -readonly -nobrowse -mountpoint "$S" >/dev/null
hdiutil attach "$CX"  -readonly -nobrowse -mountpoint "$C" >/dev/null
echo "[*] copying rootfs -> new image ..."
ditto "$S" "$N"
echo "[*] copying cryptex -> /private/preboot/Cryptexes/OS ..."
D="$N/private/preboot/Cryptexes/OS"; mkdir -p "$D"; ditto "$C" "$D"
df -h "$N" | tail -1
ls -la "$D/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e" 2>/dev/null
sync
echo "[OK] $OUT   ->   ROOTFS=$OUT ./run_rootfs.sh"
