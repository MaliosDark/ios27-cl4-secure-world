#!/usr/bin/env python3
"""darwin-vm boot-log triage.

Read-only. Parses a darwin-vm serial/boot log and reports, in boot order,
which milestones were reached and which walls are still blocking. Use it after
step 3 of RUNBOOK_darwinvm_cryptex_boot.md to see at a glance how far the
patched kernelcache got.

Usage:
    python3 scripts/darwinvm_boot_triage.py /tmp/darwinvm_boot.log

No firmware access; it only reads the text log you give it.
"""

import re
import sys

# Ordered boot milestones. Each: (label, regex, "good"|"info").
# "good" milestones are progress; reaching a later one implies the earlier ran.
MILESTONES = [
    ("SPTM handoff to XNU",        r"bkc runtime base|slide\s+0x20000000", "info"),
    ("CL4 secure kernel up",       r"\[cl4\].*entry|secure kernel:", "good"),
    ("XNU banner",                 r"Darwin Kernel Version|BSD root", "good"),
    ("APFS root mount",            r"apfs.*mountroot|mounted?\s+root|rootfs on md0", "good"),
    ("launchd exec (PID 1)",       r"/sbin/launchd|launchd\[1\]", "good"),
    ("dyld cache mapped",          r"dyld.*shared cache.*mapped|mapping cache into shared region.*ok", "good"),
    ("libSystem loaded",           r"libSystem|dyld\[1\].*libSystem", "good"),
    ("first userspace daemon",     r"com\.apple\.(xpc|logd|notifyd|configd)", "good"),
    ("SpringBoard",                r"SpringBoard|FrontBoard|backboardd", "good"),
]

# Known walls. Each: (label, regex, hint, cleared_by).
WALLS = [
    ("Image4 magazine / nonce (no SEP)",
     r"magazine\[[^\]]*\]: failed to read nonce slot data",
     "AppleImage4 can't read nonce slots without SEP.",
     "DVM-1 (darwinvm_patch_img4_magazine)"),
    ("Image4 asmb node missing",
     r"unable to setup /chosen/asmb node",
     "iBoot never created /chosen/asmb; init takes the bail path.",
     "DVM-2 (darwinvm_patch_ssv: image4_asmb_setup)"),
    ("dyld cache null / map failed",
     r"dyld cache '\(null\)' not loaded|map cache into shared region failed|check_np\(\):\s*-1",
     "Cache never registered -> dyld has no cache to map.",
     "DVM-1 + patch_img4_deadlock (validation), then re-check"),
    ("APFS needs authenticator",
     r"apfs_vfsop_mount: Need authenticator|failed to get root-snapshot-name",
     "Non-sealed root rejected by SSV auth.",
     "DVM-3 / DVM-4 (apfs seal / mount auth)"),
    ("rootvp not authenticated (bsd_init panic)",
     r"rootvp not authenticated after mounting",
     "bsd_init FSIOC_KERNEL_ROOTAUTH failed -> panic.",
     "DVM-5 (bsd_init_rootauth)"),
    ("AMFI rejects signature",
     r"AMFI.*rejecting|unsuitable CT policy",
     "Trust cache / code-signing policy rejects the cache.",
     "merge cryptex trust cache into ramdisk.tc (already done) -- re-check cdhashes"),
    ("shared region ENOMEM",
     r"shared_region_map.*errno 12|KERN_NO_SPACE|result from check_np\(\):\s*-1, errno 12",
     "Cache span can't be placed in the shared region.",
     "gated by cryptex registration (DVM-1); if it persists after, revisit VA geometry"),
    ("generic panic",
     r"panic\(cpu",
     "Kernel panic -- capture the full backtrace.",
     "map the address, find the next gate"),
    ("data abort / SError",
     r"data abort|SError|far=0x[0-9a-f]+",
     "Fault -- note the faulting address (far=).",
     "map far/pc to a device or code path"),
]


def triage(path):
    with open(path, "r", errors="replace") as f:
        text = f.read()
    lines = text.splitlines()

    print(f"[triage] {path}  ({len(lines)} lines)\n")

    print("== Milestones (boot order) ==")
    reached_any = False
    last_reached = -1
    for i, (label, rx, kind) in enumerate(MILESTONES):
        hit = re.search(rx, text, re.IGNORECASE)
        mark = "[+]" if hit else "[ ]"
        if hit:
            reached_any = True
            last_reached = i
        print(f"  {mark} {label}")
    if not reached_any:
        print("  (no known milestone matched -- is this the right log?)")

    print("\n== Walls detected ==")
    any_wall = False
    first_wall_line = None
    for label, rx, hint, cleared_by in WALLS:
        m = re.search(rx, text, re.IGNORECASE)
        if not m:
            continue
        any_wall = True
        # find the line number of the first hit
        lineno = text[: m.start()].count("\n") + 1
        if first_wall_line is None or lineno < first_wall_line[0]:
            first_wall_line = (lineno, label)
        print(f"  [!] {label}  (line {lineno})")
        print(f"        {hint}")
        print(f"        cleared by: {cleared_by}")
    if not any_wall:
        print("  none of the known walls matched.")

    print("\n== Verdict ==")
    if last_reached >= 0:
        print(f"  furthest milestone: {MILESTONES[last_reached][0]}")
    if first_wall_line:
        print(f"  earliest wall: {first_wall_line[1]} (line {first_wall_line[0]})")
        print("  -> that's the next thing to clear.")
    elif last_reached == len(MILESTONES) - 1:
        print("  SpringBoard reached. Ship a screenshot.")
    else:
        print("  no known wall -- paste the tail of the log; the stall is something new.")

    # Show last 15 non-empty lines as context for a stall.
    print("\n== Last 15 lines ==")
    tail = [l for l in lines if l.strip()][-15:]
    for l in tail:
        print(f"  {l}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <boot.log>")
        sys.exit(2)
    triage(sys.argv[1])


if __name__ == "__main__":
    main()
