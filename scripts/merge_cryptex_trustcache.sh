#!/bin/zsh
# Merge the cryptex trust cache cdhashes into the boot trust cache so AMFI trusts the
# injected dyld shared cache. Run after inject_cryptex.sh.
#   ipsw fw tc <cryptex .trustcache> -> 130 sha256 cdhashes -> append to all_hashes ->
#   build_tc.py -> ramdisk.tc
set -euo pipefail
TC=${1:?path to 094-13150-145.dmg.aea.trustcache}
cd "$(dirname "$0")/.."
cp firmware/all_hashes firmware/all_hashes.orig 2>/dev/null || true
ipsw fw tc "$TC" 2>/dev/null | grep -oE '[0-9a-f]{40}' > /tmp/cx_hashes.txt
cat firmware/all_hashes.orig /tmp/cx_hashes.txt | tr 'A-F' 'a-f' | sort -u > firmware/all_hashes
python3 scripts/dt_fixup.py >/dev/null 2>&1 || true
python3 build_tc.py firmware/all_hashes firmware/ramdisk.tc
echo "ramdisk.tc rebuilt with $(wc -l < firmware/all_hashes) cdhashes"
