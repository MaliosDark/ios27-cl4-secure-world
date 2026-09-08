#!/bin/bash
# Wall #3 fix: re-own the darwin-vm rootfs to root:wheel so launchd will load the
# LaunchDaemons (SpringBoard, backboardd, ...). The rootfs dmg was built on macOS, so
# every file is owned by uid 501:20 instead of the iOS-correct root:wheel(0:0), and
# launchd rejects daemon plists with "bad ownership/permissions (error 122)".
#
# Run this with sudo:   sudo ./fix_rootfs_ownership.sh
#
# It attaches rootfs_with_cryptex.dmg read-write, chowns the whole volume to root:wheel,
# restores /private/var/mobile to the mobile user (501:501), then unmounts. Content is
# not modified, so the dyld-cache / trust-cache re-sign is unaffected.
set -euo pipefail

if [[ "$(id -u)" != "0" ]]; then
  echo "must run as root:  sudo $0" >&2
  exit 1
fi

DVM="$(cd "$(dirname "$0")" && pwd)"
DMG="$DVM/firmware/rootfs_with_cryptex.dmg"
[[ -f "$DMG" ]] || { echo "not found: $DMG" >&2; exit 1; }

MP="$(mktemp -d /tmp/rootfs_own.XXXXXX)"
echo "attaching $DMG ..."
hdiutil attach -readwrite -nomount "$DMG" >/dev/null
sleep 1
DISK="$(diskutil list | awk '/RaveSeedD47OS/{print $NF}' | tail -1)"
[[ -n "$DISK" ]] || { echo "RaveSeedD47OS volume not found" >&2; exit 1; }
echo "volume: $DISK -> $MP"
mount_apfs "/dev/$DISK" "$MP"

cleanup() {
  sync
  diskutil unmount "$MP" >/dev/null 2>&1 || umount "$MP" 2>/dev/null || true
  DISKID="$(echo "$DISK" | sed 's/s[0-9]*$//')"
  hdiutil detach "/dev/$DISKID" >/dev/null 2>&1 || true
  rmdir "$MP" 2>/dev/null || true
}
trap cleanup EXIT

echo "chown -R root:wheel (whole volume) ... this takes a few minutes"
chown -R 0:0 "$MP"

echo "restore /private/var/mobile -> mobile (501:501)"
[[ -d "$MP/private/var/mobile" ]] && chown -R 501:501 "$MP/private/var/mobile" || true

echo "verify:"
ls -lan "$MP/System/Library/LaunchDaemons/com.apple.SpringBoard.plist" 2>/dev/null || true
echo "done. Re-owned rootfs. Boot with:  BOOTKC=firmware/bootkc.md0.nopf4 ./run_rootfs.sh"
