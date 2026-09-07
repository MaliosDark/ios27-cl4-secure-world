#!/bin/zsh
# inject_cryptex.sh — descifra (si hace falta) el Cryptex1,SystemOS y arma un
# rootfs de iOS 27 que LO CONTIENE en /private/preboot/Cryptexes/OS, para que
# /sbin/launchd encuentre el dyld_shared_cache y libSystem.B.dylib.
#
# El rootfs original es un volumen APFS "justo" (sin espacio libre), así que NO
# se puede convertir a UDRW y agrandar: se crea una imagen APFS nueva de 20GB y
# se copian dentro el rootfs + el cryptex. (Sin sudo: los archivos quedan owned
# por tu uid pero world-readable; root en el guest mapea el cache igual.)
#
# USO:  ./inject_cryptex.sh <cryptex 094-13150-145.dmg.aea | .dmg>
# SALIDA: firmware/rootfs_with_cryptex.dmg   ->   ROOTFS=... ./run_rootfs.sh
set -euo pipefail
HERE=${0:a:h}; cd "$HERE"
IN=${1:?ruta al Cryptex1,SystemOS (.dmg.aea o .dmg)}
SRC=rootfs/24A5430a__iPhone17,3/decrypted/094-13182-141.dmg
OUT=firmware/rootfs_with_cryptex.dmg
WORK=cryptex/work; mkdir -p "$WORK"

CX="$IN"
if [[ "$IN" == *.aea ]]; then
  echo "[*] descifrando cryptex AEA (ipsw baja la fcs-key de Apple; no imprime claves)..."
  ipsw fw aea -o "$WORK" "$IN"
  CX=$(find "$WORK" -maxdepth 1 -name '*.dmg' -size +1G | head -1)
fi
[[ -f "$CX" ]] || { echo "no hay cryptex dmg"; exit 1; }
echo "[*] cryptex: $CX"

rm -f "$OUT"
echo "[*] creando imagen APFS 20GB ..."
hdiutil create -size 20g -fs APFS -volname iOSRoot -layout GPTSPUD -type UDIF "$OUT" >/dev/null
N=$(mktemp -d /tmp/new.XXXX); S=$(mktemp -d /tmp/src.XXXX); C=$(mktemp -d /tmp/cxs.XXXX)
cleanup(){ for m in "$N" "$S" "$C"; do hdiutil detach "$m" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
hdiutil attach "$OUT" -nobrowse -mountpoint "$N" >/dev/null
hdiutil attach "$SRC" -readonly -nobrowse -mountpoint "$S" >/dev/null
hdiutil attach "$CX"  -readonly -nobrowse -mountpoint "$C" >/dev/null
echo "[*] copiando rootfs -> imagen nueva ..."
ditto "$S" "$N"
echo "[*] copiando cryptex -> /private/preboot/Cryptexes/OS ..."
D="$N/private/preboot/Cryptexes/OS"; mkdir -p "$D"; ditto "$C" "$D"
df -h "$N" | tail -1
ls -la "$D/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e" 2>/dev/null
sync
echo "[OK] $OUT   ->   ROOTFS=$OUT ./run_rootfs.sh"
