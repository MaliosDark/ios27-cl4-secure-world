#!/bin/zsh
# inject_cryptex.sh — mete el Cryptex1,SystemOS (dyld shared cache + dylibs del
# sistema) dentro del rootfs de iOS 27 en /private/preboot/Cryptexes/OS, para que
# /sbin/launchd encuentre /usr/lib/libSystem.B.dylib via el shared cache.
#
# El rootfs (094-13182-141) es el SystemOS "partido": NO trae dylibs ni el
# dyld_shared_cache. Esos viven en el Cryptex1,SystemOS (~2.3GB), que debes
# descargar/descifrar tu (constraint: firmware handling es tu parte).
#
# USO:
#   scripts/inject_cryptex.sh <cryptex_descifrado.dmg>
#
# Deja un rootfs nuevo escribible en firmware/rootfs_with_cryptex.dmg listo para
# arrancar con -bootkc firmware/bootkc.md0 -dtree firmware/dtree_ios.
set -euo pipefail
HERE=${0:a:h}
CRYPTEX_DMG=${1:?ruta al Cryptex1,SystemOS descifrado (.dmg)}
ROOT_SRC=$HERE/rootfs/24A5430a__iPhone17,3/decrypted/094-13182-141.dmg
OUT=$HERE/firmware/rootfs_with_cryptex.dmg

echo "[*] copiando rootfs a un dmg escribible (shadow)..."
rm -f "$OUT"
# convertir a UDRW (read/write) para poder inyectar
hdiutil convert "$ROOT_SRC" -format UDRW -o "$OUT"

RMNT=$(mktemp -d /tmp/rw.XXXX)
CMNT=$(mktemp -d /tmp/cx.XXXX)
cleanup(){ hdiutil detach "$RMNT" >/dev/null 2>&1 || true; hdiutil detach "$CMNT" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] montando rootfs escribible..."
hdiutil attach "$OUT" -owners on -nobrowse -mountpoint "$RMNT" >/dev/null
echo "[*] montando cryptex read-only..."
hdiutil attach "$CRYPTEX_DMG" -readonly -nobrowse -mountpoint "$CMNT" >/dev/null

echo "[*] cryptex contiene:"; ls "$CMNT" | head
echo "[*] copiando cryptex -> /private/preboot/Cryptexes/OS ..."
DEST="$RMNT/private/preboot/Cryptexes/OS"
mkdir -p "$DEST"
# el cryptex tradicionalmente se monta como una carpeta con System/ dentro
sudo ditto "$CMNT" "$DEST"

echo "[*] verificando dyld_shared_cache dentro del rootfs..."
find "$DEST" -iname 'dyld_shared_cache*' | head
echo "[*] verificando libSystem.B.dylib alcanzable..."
find "$DEST" -name 'libSystem.B.dylib' 2>/dev/null | head

echo "[OK] rootfs con cryptex: $OUT"
echo "    arranca:  KC=firmware/bootkc.md0 DT=firmware/dtree_ios RD=$OUT ./run_rootfs.sh"
