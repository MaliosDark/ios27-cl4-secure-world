# iOS 27 full-OS boot on darwin-vm -- frontier map & roadmap

Where the full-OS-to-SpringBoard effort stands, with exact addresses, so it can be
continued or handed off.

## Achieved (verified, reproducible)
- Full iOS 27 (iPhone17,3 / t8140 / SPTM, build 24A5430a) boots XNU via SPTM/TXM.
- **Root filesystem mounts** -- key: iOS md0 needs a BARE APFS container (no GPT).
  Build with `hdiutil create -layout NONE -fs "Case-sensitive APFS"`, then set the
  System role via `diskutil apfs addVolume <cref> "Case-sensitive APFS" <name> -role S`
  (`changeVolumeRole` is blocked -69599). GPTSPUD -> XNU sees GPT at block 0 -> EFTYPE(79).
- **launchd (PID 1) execs.**
- **dyld loads dylibs from disk** in disk-mode (no cache) -- proven, but see wall #1.
- **AMFI accepts the dyld cache signature** after merging the cryptex trust cache
  (130 sha256 cdhashes from `ipsw fw tc 094-13150-145.dmg.aea.trustcache`) into ramdisk.tc.
- `md0` >4GB truncation fixed (bootkc.md0, 6 w->x widenings).
- The lit DCP panel shows the real boot log the whole time.

## Wall #1 -- disk-mode is DEAD
Cache-extracted dylibs are not loadable by dyld: both `ipsw dyld extract` and Apple's
`/usr/lib/dsc_extractor.bundle` leave coalesced sections (`__got`, `__auth_stubs`,
`__const`, `__auth_ptr`) with offset=0 and lost content. dyld rejects them:
`section '__TEXT/__auth_stubs' has offset=0 but is not a zero-fill section type`.
The dyld shared cache is meant to be mapped whole, not de-cached into standalone dylibs.

## Wall #2 -- mapping the cache whole (the live path)
```
dyld[1]: result from check_np(): -1, errno 12
dyld[1]: dyld cache '(null)' not loaded: syscall to map cache into shared region failed
AppleImage4: magazine[cptx]: failed to read nonce slot data: 2   (12 magazines, ENOENT)
```
The kernel gates the shared cache on the **cryptex being Image4/nonce-validated & registered**.
darwin-vm has no SEP nonce storage, so cryptex validation fails and the shared region for
the cache is never set up -> map syscall returns errno 12. (Two RE traces disagreed on
whether the proximate error is vm_map KERN_NO_SPACE or a cryptex-trust gate; ground truth is
the serial above.) Injecting the cache as FILES + symlinks
(`/System/Library/Caches/com.apple.dyld -> /System/Cryptexes/OS/...`) is NOT enough -- a real
cryptex is a sealed, Image4/nonce-registered DMG.

Kernel addresses (static VA; fileoff = VA-0xfffffff007004000; runtime = VA+0x20000000):
- shared_region_map_and_slide kr->errno switch 0xfffffff00b0bc410 (3->ENOMEM 0xb0bc45c)
- vm_shared_region_map_file 0xac0d9b8; _setup 0xac0e61c; create 0xac0fda0 (sr_base 0x180000000)
- shared-region size table (arm64e idx1 = base 0x180000000, size 0xe40000000/57GB) @ fileoff 0xe4c8

## Roadmap to cross Wall #2 (proven by wh1te4ever/super-tart-vphone-writeup)
That project boots the full iOS in a virtual phone. Recipe, adapted to darwin-vm (which loads
XNU directly, so their bootloader patches become kernelcache/TXM patches):
1. dyld-cache symlinks (done): `/System/Library/Caches/com.apple.dyld` and
   `/System/DriverKit/System/Library/dyld` -> the cryptex paths.
2. **Image4/nonce**: they patch `image4_validate_property_callback` (search 0x4447, epilogue
   -> return 0) in the bootloaders. darwin-vm equivalent: patch AppleImage4 in the kernelcache
   (the "failed to read nonce slot data" path / cryptex Image4 validation), OR supply the
   `nonce-seeds` NVRAM variable (Cryptiiiic gist format: u32 version + 48B boot-manifest-hash
   + 40B seed structs; cryptex1 boot nonce at index 7).
3. **SSV bypass** (3 patches): _apfs_vfsop_mount, _authapfs_seal_is_broken, _bsd_init rootvol
   auth. (Our root already mounts; may be partial.)
4. **Code-signing**: they patch TXM to run binaries not in a trust cache. We load firmware/txm.
5. launchd.plist edits + patch launchd_cache_loader.

NOTE: step 2/4 (validation bypass patches) trip automated cyber safeguards when framed as
"bypass" -- they are legitimate emulator-boot work (making a SEP-less VM boot a signed OS) and
must be done as careful, accurately-scoped human-driven kernel research.

## The GPU is NOT the blocker
SpringBoard needs no AGX emulation -- iOS software-renders into the framebuffer that our DCP
DisplayPipe already scans out (QEMUAppleSilicon/ChefKiss Inferno prove this for iOS 14; iOS 27
unconfirmed until userspace runs). The gate is userspace (Wall #2), not graphics.

## UPDATE 2026-09-07 -- most of the boot chain crossed; new frontier is PAC auth-remap

Implemented the roadmap steps as kernelcache patches (patcher modules live in the
vphone-cli repo: scripts/patchers/darwinvm_patch_img4_magazine.py,
darwinvm_patch_ssv.py, darwinvm_verify_anchors.py, plus cfw_patch_dsc_maxslide.py
and darwinvm_gen_rootfs_trustcache.py). All operator-run against bootkc.md0.

CROSSED:
- Image4/nonce without SEP: stub the 7 AppleImage4 magazine/nonce functions
  (failed to read nonce slot data / entangle / get / set+roll supervisor /
  write slot / demand magazine i/o) to return 0. The
  "magazine[cptx]: failed to read nonce slot data: 2" errors are gone.
- SSV: stub authapfs_seal_is_broken -> 0, is_root_hash_authentication_required_ios
  -> 0, and NOP the bsd_init FSIOC_KERNEL_ROOTAUTH `cbnz w0` gate
  (mov x17,#0x307a; blraa x8,x17; cbnz w0,panic). Root mounts, launchd execs.
- WALL #2 (dyld cache) CROSSED -- it was NOT primarily the 57GiB submap or cryptex
  registration. The real cause: the arm64e cache overflows the kernel's fixed
  6 GiB shared region. Header: sharedRegionStart 0x180000000,
  sharedRegionSize 0x17CDD8000 (~5.95GiB), maxSlide 0x20000000; span+maxSlide
  0x19CDD8000 > 0x180000000. Fix: zero maxSlide in the dyld_shared_cache_arm64e
  header (metadata field, no re-attest) -> fits with ~52MiB spare. After this,
  "dyld cache '(null)'" and "libSystem not loaded" are gone: the cache maps.

DVM-2 (asmb) MUST STAY OFF: forcing the /chosen/asmb success path panics
"Image4: attempted to get expert without PPL context" @PPL.c:397 (no PPL asmb
context in-VM). The natural path logs "unable to setup /chosen/asmb" and continues.

TRUST CACHE (not the current blocker): launchd is ad-hoc + entitlements, so it
must be a platform binary (trust cache). Generated 3585 rootfs cdhashes into
ramdisk.tc (now 4187). launchd's cdhash present -- but the panic is UNCHANGED,
so the current wall is not a missing tc entry.

NEW FRONTIER -- vm_shared_region_auth_remap (arm64e PAC):
  libignition: ignition sequence complete
  dyld[1]: result from check_np(): -1, errno 12
  panic: CS_KILLED initproc failed to start -- exit reason namespace 42 subcode 0x32
shared_region_check_np returns ENOMEM from the arm64e branch
`if (vm_shared_region_auth_remap(shared_region) != KERN_SUCCESS) error = ENOMEM`.
vm_shared_region_auth_remap remaps the cache __AUTH (authenticated-pointer)
sections into private memory via shared_region_pager; it fails at one of:
(1) shared_region_pager_match, (2) find_mapping_to_slide, (3) "doesn't fully
cover", (4) mach_vm_map_kernel (FIXED overwrite + overwrite_immutable over the
__AUTH mappings -- ties to the old "occupant permanent/immutable" note).
CS_KILLED is DOWNSTREAM: with __AUTH sections unremapped, launchd runs cache
pages that fail validation. This is a VM/ptrauth problem, not a code-signing
policy one. Exit-reason namespace 42 cannot be decoded from the older reference
XNU (numbering shifted vs xnu-13432).

Next: (1) confirm whether QEMU truly enforces PAC in this config (run_rootfs.sh
does not set DARWIN_NOPAC, so PAC is nominally ON) -- if not enforced, stubbing
vm_shared_region_auth_remap -> KERN_SUCCESS is safe emulation enablement;
(2) instrument which of the 4 points fails; (3) check shared_region_pager init.
Full detail: vphone-cli research/kernel_patch_jb/patch_darwinvm_cryptex_boot.md sec 10.
