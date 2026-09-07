# Next step: the Cryptex1,SystemOS (dyld shared cache)

## Where we are (huge milestone, already reached)
The COMPLETE iOS 27 boots through SPTM/XNU, mounts its **real root filesystem** (md0,
apfs mountroot) and starts `/sbin/launchd` (PID 1). The md0 fix (6 instructions
w->x, firmware/bootkc.md0) removed the 32-bit truncation that prevented mounting.

## The only blocker now
`launchd[1]` panics: *"Library not loaded: /usr/lib/libSystem.B.dylib ... no dyld cache"*.

**Cause (confirmed 100%):** the rootfs `094-13182-141` is the **split SystemOS**.
It does NOT contain the system dylibs or the `dyld_shared_cache`. Evidence:
- `/usr/lib/libSystem.B.dylib` does NOT exist (only the `_asan` variant).
- `/private/preboot/Cryptexes/` is EMPTY.
- `dyld` looks for the cache in `/System/Cryptexes/OS` -> `/private/preboot/Cryptexes/OS/`.

Those dylibs + the shared cache live in the **Cryptex1,SystemOS** (~2.3GB), which is
NOT downloaded. Present locally: rootfs (094-13182-141), ExclaveOS
(094-14052-182), restore ramdisk (094-13753-197). Missing: the Cryptex1,SystemOS.

## What you need to do (firmware handling = your part)
1. From the 24A5430a / iPhone17,3 IPSW, take the **Cryptex1,SystemOS** component
   (the ~2.3GB `.dmg.aea` - the same kind of AEA you already decrypted for the rootfs).
2. Decrypt it with the same method/key you used for 094-13182-141.dmg.aea.

## What the tooling does (already done)
    ./inject_cryptex.sh /path/to/Cryptex1_SystemOS_decrypted.dmg
This converts the rootfs to writable, places the cryptex in
`/private/preboot/Cryptexes/OS`, verifies that `dyld_shared_cache*` and
`libSystem.B.dylib` show up, and leaves `firmware/rootfs_with_cryptex.dmg`.

Then boot:
    ROOTFS=firmware/rootfs_with_cryptex.dmg ./run_rootfs.sh
(run_rootfs.sh already uses bootkc.md0 by default -> mounts root).

## Honest expectation after the cryptex
launchd will find libSystem and start daemons. But **SpringBoard (the UI)
needs the AGX GPU**, which is NOT emulated in darwin-vm/qemu. So after the
cryptex we expect: more daemons starting and then faults/panics in services that
touch non-emulated hardware (GPU, various coprocessors). The "screen" that does
render today is the emulated DCP panel with the real boot LOG (Boot A).
The path to real UI pixels = emulate AGX + decode IOMFB surfaces in
apple_dcp.c, both huge and also gated by the cryptex.
