# darwin-vm cryptex/SSV boot patch chain

## 1. Patch Metadata

- Patch IDs: `DVM-1` (img4 magazine) ... `DVM-5` (bsd_init root-auth)
- Related patcher modules:
  - `scripts/darwinvm/darwinvm_patch_img4_magazine.py`
  - `scripts/darwinvm/darwinvm_patch_ssv.py`
- Analysis date: 2026-09-07
- Analyst note: static analysis only. Patchers self-print before/after and gate
  on expected instruction shapes. Execution against firmware is operator-run.

## 2. Patch Goal

Let an Intel-Mac `darwin-vm` (qemu-sptm, `-M darwin`) boot iOS 27
(iPhone17,3 / t8140 / d47ap, build 24A5430a) past userspace bring-up. The
kernelcache boots, mounts a non-sealed APFS root, and execs launchd, but
launchd cannot load `libSystem` because the dyld shared cache (shipped inside
the `Cryptex1,SystemOS`) never maps into the shared region. The map is gated on
the cryptex being Image4/nonce-validated and the root passing SSV auth. Because
darwin-vm has no SEP and no iBoot, both gates fail:

```
AppleImage4: magazine[cptx]: failed to read nonce slot data: 2   (x12 domains)
dyld[1]: dyld cache '(null)' not loaded: syscall to map cache into shared region failed
apfs_vfsop_mount: Need authenticator (81)
Image4: unable to setup /chosen/asmb node
```

This chain is the kernel-side equivalent of the boot-chain patches this repo
already applies for the vphone600/CloudOS path (`image4_validate_property_callback`
signature bypass, `patch_bsd_init_auth`, `patch_io_secure_bsd_root`), retargeted
to the darwin-vm iOS 27 kernelcache.

## 3. Target Function(s) and Binary Location

Kernelcache: MH_FILESET, static base VA `0xfffffff007004000`
(darwin-vm runtime slide `0x20000000`).

| ID | Component (fileset entry) | Anchor string | Action |
|----|---------------------------|---------------|--------|
| DVM-1 | `com.apple.security.AppleImage4` | `failed to read nonce slot data` | stub -> return 0 |
| DVM-1 | `com.apple.security.AppleImage4` | `failed to entangle nonce` / `failed to get nonce:` / `demand magazine i/o failed` / `failed to {set,roll} supervisor nonce` / `failed to write slot after rolling` | stub -> return 0 |
| DVM-2 | `com.apple.security.Image4` | `unable to setup /chosen/asmb node` | NOP bail gate |
| DVM-3 | `com.apple.filesystems.apfs` | `authapfs_seal_is_broken` | stub -> return 0 |
| DVM-4 | `com.apple.filesystems.apfs` | `is_root_hash_authentication_required_ios` (fallback: `is_root_hash_authentication_required`) | stub -> return 0 (auth not required) |
| DVM-5 | kernel `__TEXT_EXEC` | `rootvp not authenticated after mounting` | NOP the `cbnz w0` guarding the panic |

Confirmed VAs (verify pass over `firmware/bootkc.md0`, static base `0xfffffff007004000`):

DVM-1 (all PACIBSP entries, stub -> return 0, PAC/RETAB):
- nonce_slot_read       func `0xFFFFFFF008F8EF54`  (xref `0xFFFFFFF008F8EFC4`)
- nonce_entangle        func `0xFFFFFFF008F7C480`  (xref `0xFFFFFFF008F7C57C`)
- nonce_get             func `0xFFFFFFF008F87240`  (xref `0xFFFFFFF008F8731C`)
- magazine_io           func `0xFFFFFFF008F845A0`  (xref `0xFFFFFFF008F84600`)
- nonce_set_supervisor  func `0xFFFFFFF008F87240`  (same fn as nonce_get)
- nonce_roll_supervisor func `0xFFFFFFF008F82CA0`  (xref `0xFFFFFFF008F82EB0`)
- nonce_write_slot      func `0xFFFFFFF008F8462C`  (xref `0xFFFFFFF008F84684`)

DVM-2 image4_asmb_setup: NOP `cbz w0` gate at VA `0xFFFFFFF00A78AE74`
  (xref `0xFFFFFFF00A78AE8C`; success path falls through to `bl 0xA78B974`).

DVM-3 apfs_seal_is_broken: stub func `0xFFFFFFF00A856958` (PACIBSP) -> return 0.

DVM-4 is_root_hash_authentication_required_ios: stub func `0xFFFFFFF00A8E0B28`
  (PACIBSP; string VA `0xFFFFFFF007D51439`, xref `0xFFFFFFF00A8E0B74`) -> return 0.

DVM-5 bsd_init root-auth: NOP `cbnz w0` gate at VA `0xFFFFFFF00AFB7B98`.
  Canonical site: `mov x17,#0x307a; blraa x8,x17` (FSIOC_KERNEL_ROOTAUTH) then
  `cbnz w0, 0xFFFFFFF00AFB7DF8` (panic block; string xref `0xFFFFFFF00AFB7E08`).

## 4. Kernel Source File Location

- Image4 magazine/nonce: private (`AppleImage4.kext`). No XNU source. Semantics
  cross-checked against `research/reference/xnu/EXTERNAL_HEADERS/img4/nonce.h`
  (nonce domain enum; `IMG4_NONCE_DOMAIN_INDEX_CRYPTEX1_BOOT = 7`).
- SSV seal/mount: private (`apfs.kext`). No XNU source.
- bsd_init: `research/reference/xnu/bsd/kern/bsd_init.c`
  (`FSIOC_KERNEL_ROOTAUTH` block; `panic("rootvp not authenticated after mounting")`).
- Confidence: img4/apfs = medium (private, string-anchored); bsd_init = high
  (open XNU + sanctioned reveal flow).

## 5. Function Call Stack

```
AppleImage4::start
  -> magazine init  (DVM-1: nonce slot read / entangle / get / io)
Image4::setupDeviceTreeNodes
  -> /chosen, /product, /defaults, /chosen/manifest-properties, /chosen/asmb  (DVM-2)
bsd_init (kernel_bootstrap_thread)
  -> vfs_mountroot -> apfs_vfsop_mount   (DVM-3 seal, DVM-4 authenticator)
  -> IOSecureBSDRoot
  -> VNOP_IOCTL(FSIOC_KERNEL_ROOTAUTH)   (DVM-5 gate -> panic on failure)
```

## 6. Patch Hit Points

Patchers emit before/after per site at runtime. Canonical stub is the same as
the existing `patch_img4_deadlock` in qemu-sptm/hw/arm/xnu_patch.c:

```
PACIBSP        ; D5 03 23 7F   (kept)
MOV  X0, #0    ; overwrite insn[1]
RETAB          ; D6 5F 0F FF   overwrite insn[2]
```

Gate NOPs (DVM-2/4/5) overwrite one conditional branch with `NOP` (`1F 20 03 D5`),
preserving the surrounding compare/call/state so only the bail decision changes.

## 7. Current Patch Search Logic

- String anchor in the component `__TEXT,__cstring` (or top-level `__TEXT` for
  bsd_init), matched by substring, resolved to its VA.
- ADRP+ADD xref search across the component `__TEXT_EXEC` (page + pageoff match).
- For stubs: walk back <= 512 insns to `PACIBSP` or `STP x29,x30` prologue.
- For gate NOPs: nearest `cbz/cbnz/tbz/tbnz` (preferring the one immediately
  before the log/panic xref).
- Uniqueness: first resolved anchor wins; multi-anchor lists provide fallbacks.
- Ambiguity handling: if no gate/prologue is found, the patcher prints a
  "manual review needed" note and applies nothing for that site.

## 8. Verification Required Before Boot

Because the operator runs these against firmware, confirm the printed before/after:

- DVM-1 stubs must sit on a `PACIBSP`-prologue function (not mid-function).
- DVM-2/4/5 NOP must land on a conditional branch whose taken-edge reaches the
  log/panic block (not an unrelated loop test).
- Re-run with `--dry-run` first; diff the reported VAs against the addresses in
  section 3 above.

## 9. Coupling Note

DVM-2 (populating/accepting `/chosen/asmb`) does not, by itself, satisfy
validation: a real asmb carries an Apple-TSS-signed IM4M that cannot be forged
for an emulated device. The asmb-setup NOP only stops the missing-node bail; the
actual accept-without-signature behavior comes from DVM-1 (magazine) plus the
existing `patch_img4_deadlock`. Treat DVM-1..DVM-5 as one set.

## 10. Boot results (2026-09-07) -- walls crossed and the current frontier

Applied against `firmware/bootkc.md0` (patched -> `bootkc.md0.patched`) with the
20 GB `dtree_ios` and `ramdisk.tc`, booting `rootfs_with_cryptex.dmg`.

### Verified crossings
- DVM-1 (7 magazine/nonce stubs), DVM-3 (apfs seal), DVM-4
  (`is_root_hash_authentication_required_ios` -> 0), DVM-5 (bsd_init root-auth
  `cbnz w0` NOP) all applied cleanly (11/11 anchors resolved; see section 3 VAs).
- The `magazine[...]: failed to read nonce slot data` errors are GONE -> Image4
  nonce validation proceeds without SEP.
- APFS root mounts (volume `RaveSeedD47OS`), `launchd` (PID 1) execs, libignition
  runs to "ignition sequence complete". `Need authenticator (81)` still logs but
  the mount completes (non-fatal).

### DVM-2 must stay OFF
Forcing the `/chosen/asmb` success path (`cbz w0` NOP at `0xA78AE74`) makes Image4
call into PPL asmb processing that panics:
`"Image4: attempted to get expert without PPL context" @PPL.c:397`.
darwin-vm has no PPL asmb context. The natural (unpatched) path just logs
"unable to setup /chosen/asmb node" and continues. So `image4_patch_ssv` keeps
DVM-2 opt-in only (`--with-asmb`); default OFF.

### Wall #2 (dyld shared cache) -- CROSSED via maxSlide=0
Symptom before: `dyld cache '(null)' not loaded: syscall to map cache into shared
region failed` + `Library not loaded: /usr/lib/libSystem.B.dylib` (panic ns 6/DYLD).
Root cause: the iOS 27 arm64e cache overflows the kernel's fixed 6 GiB shared
region: sharedRegionStart `0x180000000`, sharedRegionSize `0x17CDD8000` (~5.95 GiB),
maxSlide `0x20000000` (512 MiB); span+maxSlide `0x19CDD8000` > `0x180000000`.
Fix: `scripts/darwinvm/cfw_patch_dsc_maxslide.py` zeroes maxSlide in the cache
header (metadata, not a cs_validate'd page) -> cache fits with ~52 MiB spare.
The cache dir lives at (via symlinks)
`/System/Cryptexes/OS -> ../../private/preboot/Cryptexes/OS`,
`/System/Library/Caches/com.apple.dyld -> /System/Cryptexes/OS/System/Library/Caches/com.apple.dyld`.
Patch the main chunk `dyld_shared_cache_arm64e` in
`private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/`.
After this: `dyld cache '(null)'` and `libSystem not loaded` are GONE (cache maps).

### Trust cache expansion -- did NOT change the current wall
launchd is `com.apple.xpc.launchd`, ad-hoc (flags 0x2), cdhash
`459d729288ef0870aa6c138e8d8a0d7dda59e2ca`, WITH entitlements. Per XNU exec
(`kern_exec.c`), an ad-hoc binary WITH entitlements must be a platform binary
(trust cache) to run. `scripts/darwinvm/darwinvm_gen_rootfs_trustcache.py`
extracted 3685 rootfs cdhashes (3585 new) -> `all_hashes` 4187 entries ->
`build_tc.py` -> `ramdisk.tc`. launchd's cdhash is now present. But the panic is
UNCHANGED. So the current wall is NOT a missing trust-cache entry.

### Current frontier: `vm_shared_region_auth_remap` (arm64e PAC) -> CS_KILLED
Ground-truth serial (every post-maxSlide boot):
```
libignition: goodbye: ignition sequence complete
dyld[1]: result from check_np(): -1, errno 12
panic: CS_KILLED initproc failed to start -- exit reason namespace 42 subcode 0x32
```
`shared_region_check_np` (bsd/vm/vm_unix.c) returns `ENOMEM(12)` from the
arm64e-only branch:
```c
if ((error == 0) && (vm_shared_region_auth_remap(shared_region) != KERN_SUCCESS))
    error = ENOMEM;
```
`vm_shared_region_auth_remap` (osfmk/vm/vm_shared_region.c) remaps the cache's
authenticated-pointer (__AUTH) sections into private memory via
`shared_region_pager`. It fails at one of four points (each `printf` + return):
1. `shared_region_pager_match() failed`
2. `find_mapping_to_slide() failed`
3. `doesn't fully cover`
4. `mach_vm_map_kernel() failed`  (maps the pager with
   `VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite=true)` + `vmkf_overwrite_immutable`)
`use_ptr_auth = task_sign_pointers(task)`; the match uses `task->jop_pid`.
The `CS_KILLED` is a DOWNSTREAM effect: with the __AUTH sections not remapped,
launchd executes cache pages that fail validation -> killed. Note exit-reason
namespace 42 cannot be decoded from the (older) reference XNU; the numbering
shifted vs xnu-13432.

Point 4 ties to the earlier FRONTIER note "VM_FLAGS_OVERWRITE ... occupant
permanent/immutable": the auth pager cannot overwrite the __AUTH mappings.

### Next directions (not code-signing bypass -- a VM/ptrauth problem)
1. PAC state: `run_rootfs.sh` does NOT set `DARWIN_NOPAC`, so PAC is nominally ON.
   If QEMU does not truly enforce PAC in this config, the __AUTH sections need no
   real ptrauth remap and `vm_shared_region_auth_remap` could be stubbed to
   `KERN_SUCCESS` (skip) as emulation enablement. MUST confirm PAC is not
   enforced first, else launchd faults on unauthenticated pointers.
2. Instrument which of the 4 points fails (kernel printf visibility or a probe).
3. Verify `shared_region_pager` init in darwin-vm.

## 11. auth_remap eliminated -- frontier narrows to shared-region task setup (2026-09-07)

Stubbing vm_shared_region_auth_remap (@ VA 0xFFFFFFF00B0B9C3C, prologue `bti c`)
to `return 0` did NOT change the panic: still `check_np(): -1, errno 12` +
`CS_KILLED`. So auth_remap (the arm64e __AUTH/PAC remap) is NOT the ENOMEM source.

The errno probe found exactly ONE `movz w?,#0xC` (ENOMEM) in shared_region_check_np,
at VA 0xFFFFFFF00B0BA85C (w23), right after the auth_remap-failed trace. Since
stubbing auth_remap didn't help, that ENOMEM setter is SHARED: the
vm_shared_region_update_task / vm_shared_region_start_address failure paths branch
to the same 0xB0BA85C. So the real ENOMEM comes from update_task or start_address
(the shared-region-to-task attachment), not the PAC remap.

Kernelcache facts (this build ships SHARED_REGION_TRACE strings; runtime level
suppresses them on serial):
- shared_region_check_np: VA 0xFFFFFFF00B0BA1E0 (runtime +0x20000000 = 0x2B0BA1E0)
- auth_remap call site (bl): VA 0xFFFFFFF00B0BA7DC -> auth_remap 0xFFFFFFF00B0B9C3C
- shared ENOMEM setter: VA 0xFFFFFFF00B0BA85C (movz w23,#0xC)
- trace strings: "update_task(%p) copyin failed", "region_slide(...) failed",
  "enter: lookup failed", "map(): vm_shared_region_map_file() failed"

Interpretation: the cache maps (space, via maxSlide=0) but the shared_region
OBJECT is not fully established/attached to launchd's task -- consistent with
mapping via the maxSlide route rather than the normal cryptex-registered path.
"update_task(%p) copyin failed" points at vm_shared_region_update_task.

Tools added: scripts/darwinvm/darwinvm_probe_srtrace.py (raise trace level),
darwinvm_probe_checknp_errno.py (distinct-errno probe),
darwinvm_probe_skipauthremap.py (stub auth_remap),
darwinvm_stub_fn_by_string.py (generic stub-by-internal-cstring).

Next: stub update_task / start_address by their internal strings to identify the
culprit, then lldb (break check_np @ 0x2B0BA1E0, step the 3 sub-calls, read x0) to
find WHY it fails (likely a copyin or submap-insert in the VM's address space).

## 12. Definitive narrowing: shared-region ESTABLISHMENT is broken (2026-09-07)

Elimination results (each a full boot):
- stub vm_shared_region_auth_remap -> 0 : NO change (errno 12 / CS_KILLED persist).
- stub vm_shared_region_update_task -> 0 (@ VA 0xFFFFFFF00AC0BA1C, found via
  "update_task(%p) copyin failed"): NO change.
- force shared_region_check_np success (patch the shared ENOMEM setter
  `movz w23,#0xC` @ VA 0xFFFFFFF00B0BA85C -> `movz w23,#0`): the panic CHANGES from
  `CS_KILLED ... namespace 42 subcode 0x32` to
  `initproc failed to start -- exit reason namespace 2 subcode 0xb`
  = OS_REASON_SIGNAL / SIGSEGV(11), and CS_KILLED is GONE. launchd now SEGVs
  (before libignition), because check_np handed dyld a bogus start_address.

Conclusion: the CS_KILLED was a CONSEQUENCE of check_np failing, not code-signing
policy. The real blocker is that the dyld shared cache's shared_region OBJECT is
not properly established/attached to launchd's task (vm_shared_region_start_address
returns garbage). The cache maps into the address space (so "libSystem not loaded"
is gone) but the shared-region bookkeeping is invalid -- consistent with mapping
the cache via the maxSlide route rather than the normal cryptex-registered
shared_region_map_and_slide flow. Forcing past check_np just relocates the crash
to a userspace SIGSEGV; it does not yield a working boot.

This is the genuine frontier and is NOT a quick patch: it needs the shared region
to be built correctly. Investigate the exec-time path
vm_shared_region_map_file / vm_shared_region_create / how dyld's
shared_region_map_and_slide_np populates the region, and why start_address ends up
invalid in this VM. lldb (break check_np @ runtime 0x2B0BA1E0, and the map path
during launchd exec) is the right instrument.

Copies for reference: bootkc.md0.utsk (update_task stub),
bootkc.md0.cnok (check_np forced-success -> SIGSEGV).

## 13. REFRAME: check_np errno 12 is NORMAL -- the real failure is the map syscall (2026-09-07)

Research (reading reference XNU) established the exact mechanism:
- `vm_shared_region_start_address` (vm_shared_region.c:1129) returns
  `sr_base_address + sr_first_mapping`; it fails (KERN_INVALID_ADDRESS) ONLY when
  `sr_first_mapping == (mach_vm_offset_t)-1` (region empty, :1160-1162).
- `sr_first_mapping` is initialized to -1 in vm_shared_region_create (:976) and at
  the top of vm_shared_region_map_file_setup (:1495). It is populated in EXACTLY
  one place: the mapping loop of vm_shared_region_map_file_setup, after a
  successful `vm_map_enter_mem_object_control`:
  `:1946 if (sr_first_mapping == -1) sr_first_mapping = target_address;`
  where `target_address = sms_address - sr_base_address`.
- That loop is reached ONLY via dyld's syscall
  shared_region_map_and_slide_2_np (vm_unix.c:1936) ->
  shared_region_map_and_slide_setup -> vm_shared_region_map_file (:2065) -> _setup.
- The QEMU loader does NOTHING for the shared region (grep: zero refs in darwin.c /
  xnuboot_sptm.c). It is entirely runtime, kernel-driven at the dyld syscall.

Therefore: **check_np returning errno 12 is EXPECTED** -- it is dyld's FIRST call,
before mapping, when the region is legitimately empty (sr_first_mapping == -1).
It is NOT the bug. dyld then issues shared_region_map_and_slide_2_np to populate
the region. The REAL failure is in that map syscall's vm_map_enter loop, which
does not set sr_first_mapping (the map into the nested shared submap fails). This
is why forcing check_np to "succeed" only produced a SIGSEGV: dyld skipped the
real map and used a bogus start_address.

CORRECTED TARGET: vm_shared_region_map_file_setup's mapping loop
(vm_map_enter_mem_object_control into the shared submap). With maxSlide=0 dyld maps
at slide 0 so target_address should be 0 and sr_first_mapping should become 0 --
unless the vm_map_enter FIXED map fails (e.g., a whole-span reservation /
permanent+immutable occupant in the submap blocks the fixed placement -> the old
FRONTIER "occupant permanent/immutable" note). Confirm with lldb:
  - break shared_region_map_and_slide_2_np: is it invoked? return value?
  - break the vm_map_enter in map_file_setup: does it return KERN_SUCCESS? if not,
    what error, and what occupies the target range in the submap?
  - after the syscall, is sr_first_mapping still -1?
STOP chasing check_np / auth_remap / update_task -- those are downstream of an
empty region.
