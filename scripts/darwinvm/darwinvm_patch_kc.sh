#!/bin/zsh
# darwin-vm cryptex/SSV kernelcache patch runner (secure-world edition).
# Chains DVM-1 (img4 magazine) then DVM-2..5 (SSV/root-auth) onto a copy.
# Requires a python venv with capstone + keystone. Set VENV= to point at one
# (defaults to vphone-cli's .venv if present).
set -euo pipefail
HERE="${0:a:h}"                       # .../scripts/darwinvm
REPO="${HERE:h:h}"                    # secure-world repo root
VENV="${VENV:-/Users/maliosdark/vphone-cli/.venv}"

if [[ $# -lt 1 ]]; then print -u2 "usage: $0 <bootkc.md0> [-o out] [-y]"; exit 1; fi
SRC=""; OUT=""; YES=0
while [[ $# -gt 0 ]]; do case "$1" in
  -o) OUT="$2"; shift 2;; -y|--yes) YES=1; shift;;
  -*) print -u2 "unknown flag $1"; exit 1;; *) SRC="$1"; shift;; esac; done
[[ -f "$SRC" ]] || { print -u2 "no source kc: $SRC"; exit 1; }
[[ -z "$OUT" ]] && OUT="${SRC}.patched"
STAMP="$(date +%Y%m%d-%H%M%S)"; BACKUP="${SRC}.orig.${STAMP}"
print "src=$SRC  out=$OUT  backup=$BACKUP"
cp "$SRC" "$BACKUP"; cp "$SRC" "$OUT"
[[ -f "$VENV/bin/activate" ]] && source "$VENV/bin/activate" || print -u2 "warn: no venv at $VENV"
cd "$REPO"
print "\n== Stage 1: img4 magazine (DVM-1) =="
python3 -m scripts.darwinvm.darwinvm_patch_img4_magazine "$OUT"
print "\n== Stage 2: SSV/root-auth (DVM-2..5) DRY RUN =="
python3 -m scripts.darwinvm.darwinvm_patch_ssv "$OUT" --dry-run
if [[ "$YES" -ne 1 ]]; then
  print -n "\nApply SSV stage to $OUT? [y/N] "; read -r r
  [[ "$r" == "y" || "$r" == "Y" ]] || { print "aborted (img4 already applied)"; exit 0; }
fi
print "\n== Stage 2: APPLY =="
python3 -m scripts.darwinvm.darwinvm_patch_ssv "$OUT"
print "\nDone. patched=$OUT  pristine=$BACKUP"
