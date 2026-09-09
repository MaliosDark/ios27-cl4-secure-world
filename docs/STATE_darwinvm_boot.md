# darwin-vm iOS 27 boot -- LIVE STATE (read this first)

One-screen "where are we / what's been tried" so we never re-litigate settled points.
Last updated: 2026-09-09.

### TL;DR (2026-09-09), newest work is at the BOTTOM of this file
Full iOS 27 userspace boots; SpringBoard launches and runs ~60-90 s of guest time (was ~20-31 s).
An in-kernel `mount -uw /` (clear MNT_RDONLY in apfs_vfsop_mountroot; firmware/bootkc.md0.rwroot)
extended it. Root cause of the remaining wall: /private/var is the read-write DATA volume on a real
device, and this boot mounted only the read-only SYSTEM volume, so /private/var writes EROFS. A DATA
volume was synthesized and paired into a real APFS volume group (firmware/rootfs_data.dmg;
apfs_volume_group_id + Fletcher-64 surgery), which makes the kernel ROSV shadow-fs-root path fire --
but the DATA volume is still not mounted at /private/var. LEVER 2 (kernel_mount md0s2) is PARKED
(XNU-core mount symbols stripped in this release KC). Active path: LEVER 1 (MobileStorageMounter
mount-phase) + a small userspace mount helper. See the newest sections at the end of this file.

Target: iOS 27 (iPhone17,3 / t8140 / d47ap, build 24A5430a) under jprx/darwin-vm +
qemu-sptm on an Intel Mac. Goal: reach SpringBoard.

## Boot chain status (CURRENT -- 2026-09-08)
- [x] SPTM -> XNU -> secure world (CL4)
- [x] Image4/nonce without SEP        (DVM-1 magazine stubs)
- [x] SSV seal / root-hash-auth        (DVM-3, DVM-4)
- [x] bsd_init FSIOC_KERNEL_ROOTAUTH   (DVM-5 gate NOP)
- [x] APFS root mounts (RaveSeedD47OS), launchd (PID 1) execs
- [x] dyld shared cache MAPS           (maxSlide reverted to valid; Wall #2 crossed)
- [x] launchd survives + FULL USERSPACE: hundreds of daemons launch AND RUN their code
- [x] CS_KILLED / PAC / TXM selector-38 all SOLVED (DARWIN_NOPAC=1 + txm.sc + bootkc.md0.nopf4)
- [x] SpringBoard SPAWNS and RUNS -- now ~60-90s of guest time after the in-kernel root-RW patch
      (was ~15-31s); still aborts (SIGTRAP) before rendering UI
- [x] Root mounted READ-WRITE in-kernel (clear MNT_RDONLY in apfs_vfsop_mountroot; bootkc.md0.rwroot)
- [x] DATA volume synthesized + real APFS volume group formed -> kernel ROSV shadow-fs-root fires
- [ ] DATA volume MOUNTED at /private/var  <-- CURRENT WALL (System-only boot; /private/var EROFS)
- [ ] SpringBoard SURVIVES past ~90s (blocked on writable /private/var above)
- [ ] usable UI (needs SpringBoard alive; display/DCP is a LATER wall, not the current one)
- [~] LEVER 2 kernel_mount md0s2 PARKED (XNU mount symbols stripped); LEVER 1 + helper active

## WALL as root-caused 2026-09-08 (still the mechanism; refined 2026-09-09 below)
NOTE (2026-09-09): the read-only-rootfs framing below is correct but has since been refined. Root
is now mounted READ-WRITE in-kernel and SpringBoard reaches ~60-90s, yet /private/var still EROFS
because /private/var is the DATA volume (absent), not the root mount's MNT_RDONLY. See the TL;DR at
the top and the newest sections at the end (Data volume + APFS volume group + lever 1/2).

Full iOS 27 userspace boots. SpringBoard spawns (pid e.g. [91]), runs ~15-22s, then aborts with
SIGTRAP; launchd's 3-strike consecutive-crash policy reboots ("rebooting due to critical process
crashes: SpringBoard"), which cascades into the SIGTERM logout teardown and finally the
"Halt/Restart Timed Out" panic (that panic is just the VM shutdown never completing -- a symptom,
not the cause).
EXACT cause (caught with the DARWIN_TRAPLOG EL0-trap logger + ipsw/capstone symbolication, slide=0):
all 3 SpringBoard crashes are a brk in
  -[BSUIMappedImageCache initWithUniqueIdentifier:options:]  (BaseBoardUI),
which needs a WRITABLE temp dir (dirhelper/NSTemporaryDirectory) to mmap CPBitmap image data. The
rootfs is a single READ-ONLY md0 ramdisk with no writable /private/var, so it aborts. Corroborated
by "fixup-mobile-tmp could not create /private/var/mobile/tmp: Read-only file system" and RO
socket-bind failures. This SUPERSEDES the older CS_KILLED/PAC/TXM framing (all solved) and is NOT
the display coprocessor.
FIX IN PROGRESS: give the guest a writable /var. Host-side APFS role change is refused (-69599);
runtime `mount -uw /` is refused for the sealed System-role volume (APFS: "r/w update not
allowed") and lands too late anyway. So the robust fix is a KERNEL patch to mount the md0 root
read-write at boot (APFS ROSV forces RO for the System-role volume). See the dated 2026-09-08
sections at the end for full detail.

## Historical framing below (2026-09-07) -- SUPERSEDED, kept for the trail
The 2026-09-07 sections that follow (check_np/shared-region, CS_KILLED, PAC, TXM selector-38) were
each real walls at the time and are now ALL crossed; do not treat them as the current wall.

## (old framing kept for history)
`shared_region_check_np` returns ENOMEM(12) -> launchd killed. Root cause is NOT
code-signing: it is that the dyld cache's **shared_region OBJECT is not properly
established** for launchd's task. `vm_shared_region_start_address` returns a
garbage/invalid address. The cache maps into the address space, but the kernel's
shared-region bookkeeping is invalid (we mapped via the maxSlide route, not the
normal cryptex-registered shared_region_map_and_slide flow).

## CORRECTION 2026-09-07 (late) -- the shared region is FINE; wall is code-signing
Experiment: NOP the map_file_setup mapping-failure trace gate (tbnz @ 0xAC0E8DC).
Result: NO `mapping[...] failed` and NO `map_file() failed` trace printed in any
boot. If the cache map into the shared region failed, that trace would fire. It
does not -> **the dyld cache MAPS SUCCESSFULLY into the shared region.**

Therefore:
- `check_np errno 12` is BENIGN: it is dyld's pre-map call (region legitimately
  empty BEFORE dyld maps it). NOT the bug. (Forcing check_np success -> SIGSEGV
  precisely because dyld then skips its own map and uses the empty region.)
- The whole "shared-region establishment" line (auth_remap / update_task /
  start_address / map_file_setup) is a DEAD END here -- those succeed. Do NOT
  chase them further.
- The REAL wall is launchd's `CS_KILLED` AFTER a successful cache map -- genuine
  code-signing enforcement. The static trust cache (launchd cdhash + 3585 rootfs
  cdhashes) did NOT change it -> it is TXM-level enforcement (roadmap step 4),
  not a static-trustcache miss.
- amfi-allows-trust-cache-load DT property: set 0->1 (dtree_ios.tcl), NO effect.
  AMFI reads it at init (xref 0x91A3DD4) but it does not gate launchd's validation
  (likely governs runtime/external trust-cache loads, not the static one).
- TXM DOES load the static TrustCache from /chosen/memory-map (strings: "loaded
  external trust cache modules", "unable to find TrustCache property in
  /chosen/memory-map"). Our ramdisk.tc is raw TrustCacheModule v1 (worked for the
  restore-ramdisk boot); the cryptex tc is IM4P/"trcs" (different, for cryptex).
- STATIC ANALYSIS EXHAUSTED: every tractable hypothesis eliminated; CS_KILLED
  (exit reason ns 42 subcode 0x32) persists. The exact kill decision (which TXM/
  kernel cs check rejects launchd, and why, despite its cdhash in the loaded
  static tc) can only be seen dynamically. NEXT = lldb on the QEMU gdbstub.

NEXT: identify the exact CS_KILLED cause (cs_invalid_page on a page? launch
constraint? TXM refusing the binary?). lldb: break where CS_KILLED is set
(kern_exec.c proc_csflags_set path / cs_invalid_page in vm_fault) or decode exit
reason namespace 42 subcode 0x32 in THIS kernel. This returns us to the
code-signing/TXM frontier with evidence that VM mapping is NOT the problem.

## SETTLED (do NOT re-try -- proven dead or proven-not-the-cause)
- DVM-2 (force /chosen/asmb success): DEAD -- panics "attempted to get expert
  without PPL context" @PPL.c:397. Keep asmb OFF (default).
- Disk-mode (extracted dylibs): DEAD (coalesced __auth_stubs offset=0).
- Trust cache missing launchd cdhash: NOT it -- added 3585 rootfs cdhashes
  (ramdisk.tc = 4187), CS_KILLED unchanged.
- `amfi_enforce_launch_constraints=0` boot-arg: no effect.
- Wall #2 was NOT the 57GiB submap nor cryptex-registration-for-mapping: it was
  the 6GiB shared-region overflow (cache span 0x17CDD8000 + maxSlide 0x20000000 >
  0x180000000). Fixed by maxSlide=0.
- auth_remap is NOT the ENOMEM source: stubbing vm_shared_region_auth_remap -> 0
  changed nothing.
- update_task is NOT the ENOMEM source: stubbing vm_shared_region_update_task -> 0
  changed nothing.
- Forcing check_np success (movz w23,#0xC -> #0 @ 0xFFFFFFF00B0BA85C): CS_KILLED
  -> SIGSEGV(11). (Interpretation UPDATED: not "region broken" -- dyld skipped its
  own post-checknp map and used the empty region. See CORRECTION above.)
- map_file_setup mapping-failure trace (gate NOP @ 0xAC0E8DC): NOT hit -> cache
  maps OK; shared-region path is NOT the wall.
- Launch constraints: NOT it. Stubbing mac_proc_check_launch_constraints
  (0xFFFFFFF00B306DA0) -> return 0 changed nothing.
- amfi_enforce_launch_constraints boot-arg: read from config at AMFI init
  (0x91A6398 -> parser 0x91C89D8) but setting it had no effect.
- map_file / map_file_setup failure traces (gates NOPped): never fire -> the dyld
  cache MAPS SUCCESSFULLY; shared-region path fully ruled out.

CONCLUSION: everything except TXM code-signing enforcement is eliminated. launchd
runs ("hello from launchd.1"), the cache maps, then TXM kills it (CS_KILLED,
exit reason ns 42 subcode 0x32) because it does not honor our unsigned static
trust cache. The remaining wall == roadmap step 4 (TXM accepts binaries not in a
TXM-validated trust cache). This is the sensitive code-signing step.

## Key addresses (static VA; runtime = static + 0x20000000)
- shared_region_check_np                 0xFFFFFFF00B0BA1E0  (rt 0x2B0BA1E0)
- check_np shared ENOMEM setter          0xFFFFFFF00B0BA85C  (movz w23,#0xC)
- check_np -> bl auth_remap              0xFFFFFFF00B0BA7DC  -> 0xFFFFFFF00B0B9C3C
- vm_shared_region_update_task           0xFFFFFFF00AC0BA1C  (str "update_task(%p) copyin failed")
- DVM-1 nonce_slot_read (sample)         0xFFFFFFF008F8EF54
- DVM-3 apfs_seal_is_broken              0xFFFFFFF00A856958
- DVM-4 root_hash_auth_required_ios      0xFFFFFFF00A8E0B28
- DVM-5 bsd_init rootauth gate           0xFFFFFFF00AFB7B98
- shared-region trace strings present in KC (level suppressed on serial):
  "update_task(%p) copyin failed" @0x70D4CBB, "check_np(...) auth_remap failed" @0x7101BC6

## Artifacts (in firmware/)
- bootkc.md0            pristine original
- bootkc.md0.patched    DVM-1/3/4/5 + (apply maxSlide on the cache separately)
- bootkc.md0.orig.*     timestamped backups from the runner
- bootkc.md0.utsk       .patched + update_task stub  (experiment)
- bootkc.md0.cnok       .patched + check_np forced-success (experiment -> SIGSEGV)
- rootfs_with_cryptex.dmg  cache maxSlide already zeroed; ramdisk.tc = 4187 cdhashes

## Tooling (ios27-cl4-secure-world/scripts/darwinvm/)
- darwinvm_patch_img4_magazine.py   DVM-1
- darwinvm_patch_ssv.py             DVM-2(off)/3/4/5
- darwinvm_verify_anchors.py        read-only anchor check (11/11)
- darwinvm_patch_kc.sh              runner (backup+chain)
- darwinvm_gen_rootfs_trustcache.py rootfs cdhash -> trust cache
- cfw_patch_dsc_maxslide.py         zero cache maxSlide (Wall #2 fix)
- darwinvm_probe_srtrace.py         raise shared_region_trace_level (WIP: global not auto-resolved)
- darwinvm_probe_checknp_errno.py   distinct-errno probe (found 1 shared ENOMEM site)
- darwinvm_probe_skipauthremap.py   stub auth_remap
- darwinvm_stub_fn_by_string.py     generic stub-by-internal-cstring
- darwinvm_boot_triage.py           boot-log classifier

## In flight
- lldb dynamic dive on the shared-region setup (option 1).
- research agent on vm_shared_region_map_file/create -> what populates
  sr_first_mapping and why start_address is invalid in-VM (option 2).

## Layout (everything lives in the secure-world repo)
- Home repo: /Users/maliosdark/ios27-cl4-secure-world  (this repo; git -> github MaliosDark)
- Our scripts: scripts/darwinvm/  (self-contained package; vendored _asm.py)
- Our docs: docs/  (this file, patch_darwinvm_cryptex_boot.md, FRONTIER.md, RESUME-...)
- darwin-vm (jprx upstream fork + qemu-sptm + YOUR firmware) stays at
  /Users/maliosdark/darwin-vm  (origin github.com/jprx/darwin-vm; firmware gitignored).
  Our scripts operate on /Users/maliosdark/darwin-vm/firmware/*. Not copied in
  (huge upstream); reference by path. Could be a git submodule later if desired.
- Python deps: capstone + keystone + pyimg4. Use vphone-cli's .venv, or make one:
  `python3 -m venv .venv && ./.venv/bin/pip install capstone keystone-engine pyimg4`

## How to run (from the secure-world repo root)
```
cd /Users/maliosdark/ios27-cl4-secure-world
source /Users/maliosdark/vphone-cli/.venv/bin/activate   # or a local .venv
KC=/Users/maliosdark/darwin-vm/firmware/bootkc.md0

# verify anchors (read-only)
python3 -m scripts.darwinvm.darwinvm_verify_anchors $KC
# apply DVM-1..5 (runner: backup + chain)
./scripts/darwinvm/darwinvm_patch_kc.sh $KC -y
# cache maxSlide fix (on the mounted cryptex cache dir)
python3 scripts/darwinvm/cfw_patch_dsc_maxslide.py <cache_dir>
# rootfs trust cache
python3 -m scripts.darwinvm.darwinvm_gen_rootfs_trustcache <rootfs_mount> <all_hashes_in> <all_hashes_out>
# boot-log triage
python3 scripts/darwinvm/darwinvm_boot_triage.py /tmp/darwinvm_boot.log
```

## In flight
- lldb dynamic dive on shared_region_map_and_slide_2_np / vm_shared_region_map_file_setup
  (the CORRECTED target; see REFRAME below/above). Break check_np @ rt 0x2B0BA1E0 only to
  confirm the region is empty; the real work is the map syscall's vm_map_enter loop.

## Full detail
docs/patch_darwinvm_cryptex_boot.md (sec 10-13), docs/FRONTIER.md (UPDATE 2026-09-07).

## EXACT KILLER IDENTIFIED 2026-09-07 (late) -- AMFI/TXM platform-binary check
The precise reject (AMFI cs-validation, kernel side ~0x91ADxxx):
  0x91ADD44: tbnz w8,#0x1a, skip        ; if binary is platform (cs flag bit26) -> pass
  0x91ADD48: bl 0x91A6534 (developer_mode_enabled: returns global[0xB80DA00]!=0)
  0x91ADD4C: cbz w0, 0x91ADD94          ; if !platform AND !devmode -> REJECT
  0x91ADD94: "The system only allows platform binaries until developer mode
             status has been resolved, and the code is not a platform binary"
  string 0x762D900: "Platform binary with platform identifier not in trust cache"
launchd declares a platform identifier (com.apple.xpc.launchd) but AMFI/TXM does
NOT find its cdhash as a trusted platform binary -> bit26 not set -> reject.

Experiments (all NO effect on the CS_KILLED):
- force developer_mode_enabled() -> 1 (patch 0x91A6534): no effect. launchd is
  PID 1 / initproc, which must be a PLATFORM binary regardless of dev mode; dev
  mode only relaxes adhoc for non-init processes.
- amfi-only-platform-code DT prop, amfi-allows-trust-cache-load DT prop: no effect.

ROOT (evidence-complete): iOS 27 determines platform-binary status via TXM. Our
raw unsigned TrustCacheModule v1 (ramdisk.tc, loaded from /chosen/memory-map) is
NOT honored by TXM for launchd's platform determination (it worked for the older
restore-ramdisk/bash path, but the full-OS initproc goes through TXM's strict
check). launchd's cdhash IS in our tc, but TXM's trusted set does not include it.

REMAINING OPTIONS (both hard/sensitive):
1. Patch TXM (firmware/txm, guarded world) to treat our trust cache / launchd as
   trusted platform code (roadmap step 4 -- the code-signing-monitor bypass). This
   is the sharpest dual-use step.
2. lldb to confirm exactly why TXM's lookup misses (cdhash/hashType/format/
   registration) before patching -- TXM is guarded so this is a hard session.
No non-bypass path exists: a TXM-honored trust cache requires Apple Image4 signing
we cannot produce. This is the genuine, final frontier.

## STATIC ROAD EXHAUSTED 2026-09-07 (final) -- needs lldb
More experiments, all NO effect on CS_KILLED (ns 42 / subcode 0x32, identical every time):
- force developer_mode_enabled() -> 1 (patch 0x91A6534): no effect (initproc must be platform).
- force the platform-binary gate: tbnz w8,#0x1a @ 0x91ADD44 -> unconditional b (treat as
  platform at that reject): NO effect. So the "system only allows platform binaries" reject
  at 0x91ADD94 is NOT launchd's killer.
- The exit-reason creation site cannot be found statically: `mov w?,#0x2a` (42) occurs 36+
  times (42 is a common immediate), none clearly paired with code 0x32 at an
  exit_with_reason/os_reason_create.

The CS_KILLED (ns42/subcode0x32) is IDENTICAL across every experiment and resists every
static patch we tried, which means the real kill site is one static analysis can't pinpoint.
CONCLUSION: further progress requires DYNAMIC debugging (lldb on the QEMU gdbstub) to catch
launchd's death live and read the exact cause. Static + experimental patching is exhausted.

## lldb entry (next session)
1) Boot frozen with gdbstub:  (from /Users/maliosdark/darwin-vm)
   BOOTKC=firmware/bootkc.md0.patched ROOTFS=firmware/rootfs_with_cryptex.dmg ./run_rootfs.sh -S -gdb tcp::1234
2) lldb:  gdb-remote localhost:1234   (kernel runtime = static VA + 0x20000000)
3) Catch the kill: break at the initproc-death panic 0x2AFF7AE8 and `bt`; then work back to
   where p_exit_reason (ns42/subcode0x32) is set / where launchd receives SIGKILL. The AMFI
   cs-validation is 0x91AD774 (rt 0x2B1AD774); breakpoint there and single-step launchd's
   validation to see which check actually rejects (the ones we forced were not it).
Artifacts: bootkc.md0.{devm,plat,lc,utsk,cnok,tren} = the experiment kernels (all still CS_KILLED).

## lldb ATTEMPT 2026-09-07 (late) -- feasible but a slow grind
Confirmed working: lldb (llvm 20) connects to QEMU's gdbstub; TXM is NOT slid
(runtime == static VA, e.g. lookup at 0xFFFFFFF017042020 directly), and the gdbstub
sees the guarded world, so TXM breakpoints ARE settable. Boot under the stub reaches
the same CS_KILLED panic.
Practical walls hit (why batch/background lldb didn't capture the cause):
- Boot under gdbstub is much slower; reaching launchd takes minutes, not the ~20s of
  a free run. Background batch with a fixed wait kept timing out before the stop.
- A CONDITIONAL breakpoint on the hot trust-cache lookup (0x17042020, reading $x1 each
  call) made the boot crawl (memory read per call over the stub).
- After the panic, darwin-vm leaves the CPU in a state where the gdbstub stops
  answering (handshake timeout on re-attach).
Net: catching launchd's exact rejection needs a PATIENT INTERACTIVE lldb session, not
background batch. Recipe below.

## TXM RE findings (static, complete)
- TXM accepts our trust cache format: validation @ 0xFFFFFFF017041FE0 checks
  version==1 and length == 24 + numEntries*22. Our ramdisk.tc = 92138 = 24+4187*22 ✓.
- Trust-cache lookup (binary search, 20-byte cdhash memcmp): fn @ 0xFFFFFFF017042020,
  returns 0x44 (found) / 0x2444.. (not found). memcmp helper 0x170408dc (w2=0x14=20).
- Per-hashType dispatcher: caller @ ~0xFFFFFFF0170423F0 (calls lookup at 0x1704242C),
  normalizes return (0x40 on clean) @ 0x17042470-78.
- Entry flags getter: 0xFFFFFFF017042150 (ldrb w0,[entry+0x15]); flags are RETURNED to
  AMFI (kernel) which interprets them -> flags value likely matters for platform.
- build_tc.py writes hashType=2, flags=0 for every entry.
THE ONE UNKNOWN that resolves it: does TXM's lookup FIND launchd's cdhash
(459d7292 88ef0870 aa6c138e 8d8a0d7d da59e2ca)? i.e. is it (a) not found (module not
registered / cdhash the guest computes differs), or (b) found-but-flags-insufficient?
Only lldb (read $x1 at the lookup, read the return) answers this.

## PATIENT lldb recipe (next session)
term1 (frozen, serial to file so it works headless):
  cd /Users/maliosdark/darwin-vm
  DARWIN_AIC=1 DARWIN_DART=1 DARWIN_DISP=all DARWIN_RTKIT=1 DARWIN_FB=1 \
  qemu-sptm/build/qemu-system-aarch64 -M darwin -bootkc firmware/bootkc.md0.patched \
   -dtree firmware/dtree_ios -tc firmware/ramdisk.tc -ramdisk firmware/rootfs_with_cryptex.dmg \
   -sptm firmware/sptm -txm firmware/txm -args "rd=md0 serial=3 -v wdt=-1 wlan-olyhal-abort" \
   -m 20G -serial file:/tmp/ser.log -display none -S -gdb tcp::1234
  # wait ~30s for the 17GB ramdisk load; gdbstub opens only after that.
term2 (INTERACTIVE, be patient across the multi-minute boot):
  lldb -o "gdb-remote localhost:1234" -o "br set -a 0xFFFFFFF017042020" -o "c"
  # each stop = a trust-cache lookup. Inspect the cdhash it searches:
  #   x/3xw $x1        (want 459d7292 8870ef88 ... i.e. launchd's cdhash bytes)
  # keep `c` until $x1 == launchd's cdhash (or automate a while-loop in the driver).
  # then: finish ; reg read x0   -> 0x44=found / 0x2444=not found.

## CANDIDATE FIXES to try (once lldb answers the unknown)
- If NOT FOUND due to cdhash mismatch: recompute launchd's cdhash the way the guest
  does (not macOS codesign) and rebuild the tc.
- If FOUND but flags insufficient: rebuild the tc with the correct entry flags/hashType
  (patch build_tc.py) -- LEGITIMATE, not a bypass.
- Blunt hammer (apex bypass): patch TXM lookup/dispatcher to always return found+trusted.
  Risky (entry-out/flags), build only if the above fail.
## ★ BREAKTHROUGH 2026-09-07 (lldb, DEFINITIVE) -- launchd dies from a PAC fault, NOT code-signing
Caught launchd's death live (lldb over gdbstub, bp at exit_with_reason 0xfffffff02aff6c14,
then at the fatal-exception handler 0xfffffff02affb05c). Ground truth:
- exit_with_reason called with x1=9 (SIGKILL). Reason built from a FATAL exception.
- Fatal-exception handler fmt: "ERROR: [%s:%d] FATAL exception: type=0x%x reason=0x%x
  code=0x%llx subcode=0x%llx". Captured args: TYPE=0x2a(42) REASON=1 CODE=0x32(50)
  SUBCODE=0x7884000000.
- So the panic's "exit reason namespace 42 subcode 0x32" == exception TYPE=42, CODE=50.
  Type 42 is NOT a standard Mach exception (those end ~13). It is the kernel's
  POINTER-AUTHENTICATION (PAC) FAILURE fatal.
- Delivery chain (static VAs): 0xaa627c0 -> 0xac6548c -> 0xac663b8 -> 0xaffb05c(fatal->exit).
- Frame 0xac663b8 IS the PAC-fault decoder: autda auth checks, TCR_EL1 TBI test, tests
  addr bits 53/61 (PAC signature field), reads Apple PAC ctrl regs s3_6_c15_c1_5 &
  s3_4_c15_c15_6, then hardcodes `mov w1,#0x2a` and bl 0xaffb05c. SUBCODE 0x7884000000 =
  the faulting (badly-authenticated) userspace pointer.

CONSEQUENCE -- the whole "CS_KILLED == TXM/code-signing enforcement" conclusion was WRONG.
"CS_KILLED" is just launchd_crashed_panic's label; the real kill is a PAC auth failure.
launchd IS trusted (cdhash in tc, TXM returns found/clean). It runs, maps the dyld cache,
then faults authenticating a dyld-cache __AUTH pointer -> FPAC -> fatal type 42.

ROOT CAUSE (matches old FRONTIER PAC note): the arm64e dyld shared cache __AUTH sections
carry pointers that must be signed with the process's PAC diversifier via
vm_shared_region_auth_remap / shared_region_pager. In this SEP-less VM that remap yields
wrong-key pointers, so launchd's first autda on a cache pointer FPAC-faults. Stubbing
auth_remap->KERN_SUCCESS earlier did nothing precisely because it SKIPS the resigning, so
the pointers stay wrong.

## NEXT (the real fix, three candidate routes)
1. Disable PAC enforcement in QEMU for -M darwin (env/flag) so AUT* don't fault. Check
   qemu-sptm for a NOPAC/pauth toggle. Cleanest emulation-enablement if supported.
2. Neutralize FPAC in the kernel: make the PAC-fault decoder (0xac663b8) treat the fault
   as non-fatal / skip the type-42 delivery (branch to the 0xac66904 skip path). Caveat:
   the underlying pointer is still wrong -> likely crashes elsewhere unless PAC is a
   no-op end to end.
3. Fix vm_shared_region_auth_remap so __AUTH pointers are correctly (re)signed for the
   process. Hardest; the proper fix.
Route 1 first (if QEMU emulates PAC as impdef/togglable). Faulting ptr 0x7884000000.

## ★★ DEFINITIVE ROOT CAUSE 2026-09-07 (lldb userspace backtrace) -- dyld shared-cache map fault
Full userspace backtrace of launchd's death (lldb, breakpoint on the EL0 abort handler
0xfffffff02ac663b8, saved-state has an 8-byte header so GP regs are at +0x8, pc at +0x108,
fp +0xf0, lr +0xf8). The FATAL abort (ESR 0x92000005 = data abort, translation fault L1):

  memcmp(stackbuf, x0=0x72_82000000, len=0x3ff0)    <- dyld+0x8e50 (_memcmp)
   <- dyld3::mapSplitCacheSystemWide                 dyld+0x869fc
   <- dyld3::preflightMainCacheFile                  dyld+0x87064
   <- dyld3::preflightCacheFile                      dyld+0x87634
   <- dyld4::SyscallDelegate::getDyldCache           dyld+0x1a158
   <- dyld4::start()::$_1::operator()                dyld+0x1fc4c
   <- dyld4::ProcessConfig::ProcessConfig(ctor)      dyld+0x20328
   <- dyld4::ProcessConfig::DyldCache::DyldCache     dyld+0x21d80
   <- start (__dyld_start)                           dyld+0x576c

So launchd's dyld dies while LOADING THE SHARED CACHE, in mapSplitCacheSystemWide, doing a
16 KiB memcmp whose source pointer x0 (= far) is a garbage address ~0x72xx000000 that VARIES
per boot (0x7282.., 0x75da.., 0x75e8.., 0x72ee.., 0x7884..). The other operand is a valid
16 KiB stack buffer. The kernel's EL0 abort handler classifies the bad-pointer data-abort as
a pointer-auth-style fatal (exception TYPE=0x2a=42, CODE=0x32) -> exit_with_reason(SIGKILL)
-> launchd_crashed_panic prints "CS_KILLED". The "CS_KILLED" wording is a red herring.

CONFIRMED runtime dyld == on-disk /usr/lib/dyld (memcmp at file 0x8e50 = ldr q0,[x0],#0x10
= 0x3cc10400 matches). All backtrace frames resolved against dyld's own symbol table.

## What this OVERTURNS
- NOT code-signing / TXM enforcement. launchd is trusted (cdhash in tc, TXM returns found).
  The entire "roadmap step 4 / TXM bypass / trust-cache flags" line is NOT the wall.
- NOT a page-hash cs_invalid_page (that message never prints).
- NOT the kernel shared_region_map_and_slide (those traces never fire); this is dyld's
  USERSPACE cache preflight/map (mapSplitCacheSystemWide), a different, earlier step.
- DARWIN_NOPAC=1 (this fork's built-in strip-only auth in pauth_helper.c pauth_auth) does
  NOT fix it: tested, launchd still dies identically. Proof the pointer VALUE is genuinely
  wrong, not merely mis-PAC-signed. (NOPAC also destabilises the panic path -> nested
  "PC alignment exception".)

## Prime suspect for the bad pointer
The split dyld cache: main file dyld_shared_cache_arm64e = 0xc0000 bytes (mappingCount=1,
map[0] file[0..0xbc000] vm=0x180000000, codeSignatureOffset=0), subcaches .01..77 (131 MB
each, ~5.3 GB total). We hand-edited the MAIN header (maxSlide 0x20000000 -> 0, offset 0xf0)
to fit the 6 GiB region. mapSplitCacheSystemWide computes subcache map addresses from the
main header's subCache array + mappings; a garbage ~0x72xx000000 source addr in the 16 KiB
compare is consistent with a subcache/mapping base computed wrong -> dyld reads unmapped
memory. The per-boot variation == ASLR of dyld's own mmap of the cache file(s) for preflight.

## NEXT (real fix directions, in priority order)
1. RE dyld3::mapSplitCacheSystemWide / preflightMainCacheFile (dyld+0x869fc/0x87064) to find
   exactly which cache-header field yields x0=0x72xx000000 (subCacheArrayOffset /
   subCacheArrayCount / mappingOffset / a per-subcache base). Then check whether our maxSlide
   edit or the subcache file set is inconsistent with it.
2. Reconsider the maxSlide=0 fix: it may desync the mapping math. Explore fitting the cache
   without editing signed/consistency-critical header fields, OR editing subCache offsets
   consistently, OR regenerating a coherent cache mapping.
3. Verify subcache integrity/presence and that dyld can mmap+read each (main file is only
   0xc0000 -- confirm preflight isn't reading past it into an unmapped hole).

## lldb recipe that worked (reuse)
- Boot frozen headless: qemu ... -serial file:/tmp/ser.log -display none -S -gdb tcp::1234
  (bootkc.md0.patched, ramdisk.tc, rootfs_with_cryptex.dmg). gdbstub opens ~70s after launch.
- lldb -b -s driver; settings set plugin.process.gdb-remote.packet-timeout 3600;
  gdb-remote localhost:1234. Break the EL0 abort handler 0xfffffff02ac663b8; a Python bp
  callback reads saved-state (arg0=x0), auto-continues benign page-ins (far<0x70_0000_0000),
  stops on the fatal (far>=0x70_0000_0000), then unwinds fp (+0xf0)/lr(+0xf8) and find_macho.
- NOTE: lldb -b kills the inferior on exit; each capture needs its own fresh QEMU boot.
- Key kernel VAs (runtime = static+0x20000000): exit_with_reason 0xfffffff00aff6c14;
  fatal-exception->exit handler 0xfffffff00affb05c (args proc,type,reason,code,subcode);
  PAC/abort decoder that hardcodes type-42 0xfffffff00ac663b8; launchd_crashed_panic bl
  0xfffffff00aff7ae4.

## ★★★ EXACT FAULT + ROOT CAUSE PINNED 2026-09-07 (static RE of dyld + cache header)
Traced the bad-pointer fault to dyld3::preflightCacheFile (dyld 0x8730c). Flow:
  - fstat cache file; pread(fd, stackbuf, 0x4000, 0) -> reads first 16 KiB (WORKS; header
    magic/mappings/codesig-size all validate from this buffer).
  - fcntl(fd, F_ADDFILESIGS_RETURN=0x61, {fs_blob at header codeSig off/size}) @0x875b0 --
    registers the cache's embedded code signature with the kernel.
  - mmap(addr=0, len=0x4000, prot=READ|EXEC(5), MAP_PRIVATE(2), fd, off=0) @0x87614.
  - memcmp(mmap_page, stackbuf, 0x4000) @0x87630 to prove mmap == pread.
  The memcmp FAULTS reading the mmap page (far=0x72xx000000) -> that page never faults in.

WHY the EXEC mmap page-in fails: the cache header (page 0) is inside the CodeDirectory-signed
range. Verified on the on-disk cache main file:
  codeSignatureOffset = 0xbc000, codeSignatureSize = 0x4000  (embedded sig 0xfade0cc0 @0xbc000)
  signed range = [0, 0xbc000);  maxSlide field is at offset 0xf0  -> INSIDE the signed range.
Our prior "Wall #2 fix" zeroed maxSlide (0x20000000 -> 0) at offset 0xf0 to make the cache fit
the 6 GiB shared region. That EDIT CHANGED PAGE 0, so its CodeDirectory hash no longer matches.
When the kernel validates the EXEC mmap page against the F_ADDFILESIGS-registered CodeDirectory,
page 0's hash mismatches -> the executable page is refused -> translation fault -> launchd dies
(mis-labeled CS_KILLED via the type-42 PAC-ish exception decoder).

THE maxSlide=0 FIX WAS SELF-DEFEATING: it made the cache FIT but CORRUPTED ITS SIGNATURE.
This is why every downstream theory (TXM, trust cache, PAC emulation, NOPAC) failed -- the
cache's own first page can't be mapped executable.

## CORRECT FIX (keep the cache signature intact; move the slide fix into the kernel)
Do NOT edit the cache header. Instead:
1. REVERT the cache maxSlide edit -> restore 0xf0 to 0x20000000 (valid signature, page-0 hash
   matches). Cache file is inside rootfs_with_cryptex.dmg (mount rw, patch, or rebuild).
2. Make the cache FIT without editing it: patch the KERNEL so the shared-region slide is
   forced/clamped to 0 (or enlarge the kernel shared-region size) so cache_span 0x17cdd8000
   fits in 0x180000000 with slide 0. Kernel reads cache header maxSlide (@+0xf0); find the
   read / slide randomization in vm_shared_region_map_file(_setup) and force effective slide 0.
Result: page-0 EXEC mmap validates (original bytes) AND the cache maps (slide 0 fits).
Alternative (heavier): re-sign the edited cache and add the new cdhash to the trust cache.

## ★★★★ HYPOTHESIS CONFIRMED 2026-09-07 (revert test) -- maxSlide edit was the killer
Reverted the cache maxSlide 0->0x20000000 in rootfs_with_cryptex.dmg (offset 0xf0 of
dyld_shared_cache_arm64e; valid Apple signature restored) and booted bootkc.md0.patched.
RESULT: the fatal type-42 PAC fault / "CS_KILLED ns42" is GONE. launchd got past the dyld
cache preflight. New (clean) failure:
  dyld[1]: dyld cache '(null)' not loaded: syscall to map cache into shared region failed
  dyld[1]: Library not loaded: /usr/lib/libSystem.B.dylib
  panic: launchd[1] fatal signal 6 -- namespace 6 code 0x1 (OS_REASON_DYLD / DYLIB_MISSING)
This is the ORIGINAL Wall #2 (cache doesn't fit the 6 GiB shared region with maxSlide
0x20000000), now failing cleanly in the kernel map syscall instead of corrupting page 0.
=> two facts locked: (1) our maxSlide edit caused the CS_KILLED; (2) the cache must be made
to fit WITHOUT editing it.

## NOW: fix the fit in the KERNEL (keep cache signature valid)
The map syscall (shared_region_map_and_slide_2_np -> vm_shared_region_map_file[_setup])
fails KERN_NO_SPACE(3)->ENOMEM because cache_span 0x17cdd8000 + maxSlide 0x20000000 >
region 0x180000000. maxSlide=0 (the old edit) proved the map path itself works at slide 0.
So force the kernel's effective maxSlide/slide to 0 for the cache:
- candidate: kernel fn 0xfffffff00ac2cfc0 reads maxSlide-like field [x0,#0xf0] into x24 and
  computes sr_base+maxSlide (add x27,x27,x24 @0xac2d0a4); returns 5 on the no-fit path
  (0xac2d05c). Needs confirmation that x0 is the cache header / this is the fit check.
- OR find where vm_shared_region_map_file(_setup 0xac0e61c) computes the slide from maxSlide
  and clamp to 0.
Verify dynamically (clean now -- no fatal fault): break the map syscall, find the exact
compare that yields KERN_NO_SPACE, patch it to use slide 0.
Cache in the dmg is now REVERTED (valid sig) -- keep it that way; the fix is kernel-side.

## ★★★★★ FIX B applied (cache re-signed) 2026-09-07 -- preflight FIXED, real Wall #2 unmasked
Re-signed the edited cache instead of reverting: maxSlide=0 at 0xf0, recomputed CD slot0
(sha256 of the 0x4000 page0) = fbc10976..., new cdhash = 46ac4561...643d8cfe, swapped into
all_hashes + rebuilt ramdisk.tc (build_tc.py). Cache is now ad-hoc-valid with maxSlide=0.
Verified: slot0==sha256(page0), cdhash matches the tc entry.
BOOT RESULT: the type-42 PAC fault is GONE (re-signed page0 validates via the corrected slot0
+ trusted cdhash -> dyld's preflight mmap(EXEC) page-in succeeds). BUT the map syscall STILL
fails IDENTICALLY:
  dyld[1]: dyld cache '(null)' not loaded: syscall to map cache into shared region failed
  panic: launchd[1] fatal signal 6 -- namespace 6 code 0x1 (DYLD / DYLIB_MISSING libSystem)
=> maxSlide=0 does NOT fix the map. The old "maxSlide=0 crossed Wall #2" was ENTIRELY wrong:
   it only moved the failure earlier (broke page0 sig -> preflight fault), masking the map
   failure that was there all along. The maxSlide edit was pure regression.

## REAL Wall #2 (independent of maxSlide): vm_shared_region_map_file returns kr!=0
Map path (confirmed): syscall handler @0xb0bc294 bl vm_shared_region_map_file (0xac0d9b8);
x25=kr; cbz w0 -> success switch @0xb0bc410; kr==3 -> ENOMEM. The KERN_NO_SPACE comes from a
callee of 0xac0d9b8 (nested vm_map_enter / _setup 0xac0e61c). Need the actual kr + the exact
failing sub-check (NOT maxSlide). Cache/tc now in the GOOD state (re-signed, maxSlide=0) --
keep it; debug the map with a clean (non-fatal) failure.
NEXT: lldb break 0x2b0bc298 read x0=kr; then break inside 0xac0d9b8 to find the failing call.

## ★★★★★★ WALL #2 PRECISELY LOCALIZED 2026-09-07 (lldb) -- shared-region backing (sr+0x18) is NULL
With the re-signed cache (preflight passes), traced the cache-map syscall failure to the
kernel handler (NOT vm_shared_region_map_file -- that is never reached):
  syscall handler 0xb0bc1bc -> bl 0xb0bc700 (map SETUP/copyin) @0xb0bc268; returns kr!=0 -> error
  BEFORE ever calling vm_shared_region_map_file (0xac0d9b8). That is why the map-file bp never hit.
Inside 0xb0bc700 (lldb, live):
  0xac08d44(task) -> sr = 0xffffffdfebf55d00   (task's shared region: OK, non-null)
  0xac12cb4(sr)   -> 0x0   (returns sr->[0x18]; a LOCKED getter reading field @sr+0x18)  <== NULL
  => 0xb0bc700 returns kr = 1 -> syscall fails -> dyld "map cache into shared region failed".
0xac12cb4 (0xa0 bytes): takes global lock @0xb747f18, `ldr x0,[x0,#0x18]`, returns it. So the
shared region OBJECT exists but its backing field @+0x18 (sr_map / sr_mem_entry / submap) is NULL.
The NULL path (0xb0bcd6c) checks [arg7] vs [0xb6c01b0]; mismatch -> 0xb0bca10 -> 0xb0bcdfc mov
w25,#1 (kr=1). => genuine "shared-region backing not established" -- the ORIGINAL Wall #2, now
cleanly reproduced without the maxSlide/CS detours.

## Boot chain status (updated)
- [x] dyld cache preflight passes (re-signed cache: maxSlide=0 + fixed slot0 + cdhash in tc)
- [ ] dyld cache MAPS  <-- WALL #2: sr+0x18 (shared-region backing map/mem_entry) is NULL
Everything past this (auth_remap/PAC/etc.) is downstream and moot until the cache maps.

## NEXT for Wall #2
Find who SETS sr->[0x18] (vm_shared_region_create/init or a lazy get-or-create submap) and why
it's NULL in-VM. Candidates: vm_shared_region_create ~0xac0fda0; the "get-or-create map" that
0xb0bc700 SHOULD call before 0xac12cb4. Either the sr was created without its submap, or the
setup calls the no-create getter (0xac12cb4) where it should create. Break 0xac12cb4 caller and
inspect sr fields; find the create/init that populates +0x18. This is a VM-internals fix
(possibly a targeted kernel patch to establish/allow the shared submap for the SEP-less VM).

## Artifacts state (GOOD -- keep)
- rootfs_with_cryptex.dmg: cache RE-SIGNED (maxSlide=0 @0xf0, slot0=fbc10976..., cdhash 46ac4561..)
- firmware/ramdisk.tc: rebuilt with new cache cdhash 46ac4561...; old f6d6c131 removed
- firmware/all_hashes.pre_resign, ramdisk.tc.pre_resign = backups before re-sign

## Wall #2 localized to the exact trigger 2026-09-08 (lldb)
The cache-map syscall handler (0xb0bc1bc) calls vm_shared_region_map_and_slide_setup
(0xb0bc700) BEFORE vm_shared_region_map_file. That setup returns kr=1 and the syscall fails.
Findings from live lldb (re-signed cache, so preflight passes):
- shared region is fine: base 0x180000000, size 0xe40000000 (57 GB) -> the cache (5.9 GB)
  fits trivially. sr+0x18 NULL is normal (nothing mapped yet). arg7 == global @0xb6c01b0.
  So NOT a fit/slide/arg problem.
- setup args: x0=sr-ish, x1=0x4f(79), x2=ptr, x3=0x65(101)=kr init, x4=ptr, x5/x6=out.
- The mapping loop runs ONE iteration; both map calls succeed:
    0xb31e2dc(x0,x1,prot=7,flags=0x12) -> w0=0   (vm_map_enter-like)
    0xacfa218(entry, &mapinfo@sp+0xb0, x28)  -> w0=0   (map-entry info thunk)
- BUT the map-info struct @sp+0xb0 comes back with +0x40 = 0x6300100000, i.e. the u32 at
  +0x44 ([sp+0xf4]) = 0x63 (99). The check at 0xb0bd118 `ldr w8,[sp+0xf4]; cbnz w8,0xb0bd8a8`
  then branches to the error path 0xb0bd8a8, which does address-range predicates (0xb0b9c3c)
  and unconditionally reaches `mov w25,#1` (0xb0bd91c / 0xb0be398) -> kr=1 -> syscall fails.
So Wall #2 == a non-zero property/flag (0x63) in the mapping-info at struct+0x44 makes the
setup take a kr=1 path. The map itself succeeds; this is a post-map property check.

## NEXT for Wall #2
Determine what struct+0x44 (=0x63) is and why it is non-zero here (it should be 0 for the
success path 0xb0bcf5c). Candidates: an unsupported mapping property / auth-or-slide
requirement for the arm64e cache mapping that this SEP-less VM config does not satisfy (ties
to the old auth_remap note). Break 0xacfa218's callee (thunk -> 0xacfa3e8 slow path) to see
where +0x40/+0x44 is written, and decode 0x6300100000. If it is a benign property the check
over-rejects in-VM, the fix is a targeted kernel patch at 0xb0bd118 (skip the 0xb0bd8a8 path)
or in 0xacfa218's callee; if it reflects a real unmet requirement, that requirement must be
provided. This is the true, precise Wall #2 frontier.

## ####### WALL #2 CROSSED 2026-09-08 -- launchd runs full userspace #######
Fix: NOP the over-rejecting map-info check. At 0xfffffff00b0bd11c the setup does
`ldr w8,[sp+0xf4]; cbnz w8,0xb0bd8a8` and takes a kr=1 path when the mapping-info field
struct+0x44 (=0x63 in-VM) is non-zero. That 0x63 property is benign for our purposes (the
map itself succeeds), so NOP the cbnz (0xd503201f) -> the setup completes -> kr=0 -> the dyld
cache MAPS. Built bootkc.md0.nopf4 (bootkc.md0.patched + this 1-insn NOP) and booted it.
RESULT: the dyld cache maps, libSystem loads, and launchd (PID 1) runs as full com.apple.xpc
.launchd: it does the boot-task sequence (exclaves-boot, commit-boot-mode, restore-datapartition
init-with-data-volume, fixup-mobile-tmp ...) and tries to launch backboardd, SpringBoard,
watchdogd and dozens of LaunchDaemons. 2000+ lines of userspace launchd log. This is the first
time iOS 27 userspace runs under darwin-vm.

## NEW WALL #3 -- file ownership/permissions (mundane, userspace)
launchd refuses every LaunchDaemon:
  (user/501/com.apple.SpringBoard) <Error>: Caller specified a plist with bad ownership/
  permissions: path = /System/Library/LaunchDaemons/com.apple.SpringBoard.plist, caller=launchd[1]
  Failed to bootstrap path: ... error = 122: Path had bad ownership/permissions
Cause: rootfs_with_cryptex.dmg was built on macOS, so files are owned by uid 501 (the build
user) instead of root:wheel(0:0). launchd (correctly) rejects daemon plists not owned by root.
Also seen: "/private/var/mobile/tmp: Read-only file system" (rootfs is read-only md0; expected).
FIX OPTIONS for Wall #3:
1. Re-own the rootfs to root:wheel: mount the dmg rw and `sudo chown -R 0:0` (root) the
   System/Library/LaunchDaemons (and ideally the whole tree), fix modes (plists 0644). Big but
   straightforward. Best/cleanest.
2. Make the guest ignore ownership (a mount/volume flag) -- less certain in-VM.
3. Patch launchd's ownership check (launchd is trust-cached; editing it changes its cdhash ->
   would need a tc update like the cache re-sign). Avoid if #1 works.
Do #1: chown the rootfs to root. Then SpringBoard should launch (GPU is software-rendered into
the DCP framebuffer per the frontier notes).

## Artifacts
- firmware/bootkc.md0.nopf4 = bootkc.md0.patched + NOP @0xb0bd11c (Wall #2 fix). Boot this.
- Boot cmd: BOOTKC=firmware/bootkc.md0.nopf4 (or edit run_rootfs.sh).

## IMPORTANT -- correct boot command (do not let run_rootfs.sh auto-pick)
run_rootfs.sh auto-selects the first >1G dmg in darwin-vm/rootfs/ (currently
094-13182-141.dmg, the UNfixed/UNchowned DeveloperOS image) when ROOTFS is unset. The
fixed+chowned image is firmware/rootfs_with_cryptex.dmg. ALWAYS boot with both set:
  cd /Users/maliosdark/darwin-vm
  BOOTKC=firmware/bootkc.md0.nopf4 ROOTFS=firmware/rootfs_with_cryptex.dmg ./run_rootfs.sh
Using the wrong dmg reproduces "dyld cache not loaded" + a nested PC-alignment panic (the
launchd-death panic handler), NOT our progress. The working combo that reached full userspace:
bootkc.md0.nopf4 + rootfs_with_cryptex.dmg (cache maxSlide=0x20000000 valid Apple sig; the
nopf4 kernel NOP skips the over-rejecting map-info check so the cache still maps).

## ######## 2026-09-08 -- iOS 27 USERSPACE BOOTSTRAPS; final wall = auth-remap/GOT association
With bootkc.md0.nopf4 + rootfs_with_cryptex.dmg (maxSlide reverted to 0x20000000, valid sig)
+ the rootfs re-owned to root (fix_rootfs_ownership.sh), the boot goes MUCH further:
- dyld: "dyld cache mapped system-wide: customer, auth GOTs: unmapped"
- launchd (PID 1) bootstraps the WHOLE system: hundreds of LaunchDaemons load (powerd, wifid,
  locationd, healthd, sharingd, watchdogd, containermanagerd, SpringBoard, VoiceOverTouch, ...).
  The hardware/variant rejects (securityresearchdeviceinit, dietapplecamerad, checkerboard,
  ClarityBoard: "cannot be loaded on this hardware / current os variant / boot environment")
  are NORMAL iOS behavior. Time advances to ~00:01:05. This is iOS 27 userspace running.

FINAL WALL: a flood of `TXM [Error]: selector: 38 | 42` (kernel-side generic TXM error string
@0xa2640 in bootkc). No daemon prints its own output -> daemons exec but never run their code.
Root cause chain (all confirmed by static RE of txm + kernel + the dyld log):
- The map-info check we NOP'd for Wall #2 (0xb0bd118 cbnz [sp+0xf4]=0x63 -> 0xb0bd8a8) WAS the
  arm64e auth-remap / GOT-mapping step. nopf4 SKIPS it, so the cache maps but its __AUTH GOTs
  are NOT remapped (hence dyld's "auth GOTs: unmapped").
- TXM selector 38 = the CSM "associate code region with code signature" op. Dispatch:
  main CSM dispatcher 0x1703b210 (table @0x1703b684, selector-1, max 0x37); selector 38 handler
  0x1703b234 -> 0x1703c63c -> core op 0x17032b38. That op validates the associated region is
  within the code limits ([x20+0x58]..[x20+0x60]) and carries the string
  "%s: association spans outside of code limit". Return codes live in w24 (0xc,0x12,0x13,0x17,
  0x24,0x25,... and 0x2a=42 further down). error 42 = an association failure.
- Because the auth GOTs are unmapped, every shared-cache dylib association (each daemon's dyld
  loading libSystem et al.) fails selector-38 with 42, in a tight retry spin -> boot stalls
  before SpringBoard renders.

## THE REAL FIX (final frontier): make the auth-remap SUCCEED, do not skip it
nopf4 was a shortcut that crossed Wall #2 by skipping the auth-remap; that is wrong for a full
boot. The correct fix is to make vm_shared_region_map_and_slide_setup's auth-remap path
(0xb0bd8a8, reached when map-info struct+0x44 != 0) SUCCEED instead of returning kr=1. It fails
because 0xb0b9c3c (an address-range predicate against the 0x7e5a000 table) finds an address
outside the expected region (VA-geometry mismatch in the SEP-less VM). Fix options:
1. Correct the auth-remap so the GOTs map (understand 0xb0bd8a8 / 0xb0b9c3c and why the range
   check fails; likely a VA-geometry / shared_region_pager setup issue). Cleanest; needs lldb.
2. If PAC is effectively a no-op in this QEMU config, an alternate is to make the associations
   pass without the remap (map the GOT pages plainly). Requires care.
Either way, once the auth GOTs map and selector-38 associations succeed, daemons should run and
SpringBoard should reach the framebuffer.

## Exact-reproduce
BOOTKC=firmware/bootkc.md0.nopf4 ROOTFS=firmware/rootfs_with_cryptex.dmg ./run_rootfs.sh
(rootfs re-owned to root via fix_rootfs_ownership.sh). Filter the log: grep -av 'TXM \[Error\]'.

## 2026-09-08 (late) -- userspace boots to SpringBoard-spawn; final wall = arm64e auth-GOT association CS
State of play after the auth/CS investigation (all with rootfs_with_cryptex.dmg re-owned to
root, cache maxSlide reverted/valid):

CONFIRMED working: full launchd bootstrap; backboardd, usermanagerd, pfd, centaurid, batterytrapd,
MobileGestaltHelper etc. spawn and RUN; SpringBoard [pid] reaches "service state: running".

The remaining wall has TWO layers, both rooted in the arm64e shared-cache __AUTH GOTs being
unmapped (dyld: "dyld cache mapped system-wide: customer, auth GOTs: unmapped"):
1. PAC layer: daemons that deref cache auth pointers take FPAC -> SIGTRAP and crash-loop.
   FIX FOUND: boot env DARWIN_NOPAC=1 (this qemu-sptm fork makes AUT* strip-only, no fault).
   With it, SIGTRAP crashes vanish.
2. Code-signing layer: after NOPAC, SpringBoard/tccd/locationd/usermanagerd exit with
   OS_REASON_CODESIGNING (namespace 3) code 0x2 = CODESIGNING_EXIT_REASON_INVALID_PAGE, ~300ms
   in. Root: TXM selector-38 "associate code region with signature" fails ("association spans
   outside of code limit") because the GOT region does not match the code-signature's code
   limits ([csobj+0x58]..[csobj+0x60]).

Bypasses tried (all inferior):
- txm.assoc_ok (patch TXM selector-38 to return success, firmware/txm.assoc_ok: NOP bfxil
  @0x17032fe0 + force-branch @0x17032fc4): KILLS the flood AND loads fine (=> TXM is patchable
  in this VM, SPTM does not re-verify it). BUT it fakes the return WITHOUT recording a valid
  association -> kernel then treats those pages as invalid -> OS_REASON_CODESIGNING invalid-page
  kill. So faking selector-38's *return* is wrong.
- cs_enforcement_disable=1 boot-arg: AMFI panics on purpose ("can't has cs_enforcement_disable"
  @AppleMobileFileIntegrity.cpp:5710). Patched the panic call away (bootkc.md0.csoff: NOP the
  bl @0xfffffff0091acc54 to the cs_enforcement panic thunk 0x91c7ba8) -> no panic, but the boot
  then STALLS early at ts ~00:00:28 (disabling CS enforcement breaks/spins early userspace).
  => dead end.
- Original txm (real selector-38 error 42): floods 99% of the serial (TXM error logger, kernel
  0xb043da4) -> boot crawls; with NOPAC it may or may not CS-kill (too slow to reach SpringBoard).
  Silencing the logger by NOP'ing 0xb043da4 (bootkc.md0.quiet) BROKE early boot (0 serial) --
  the logger is on a critical path; do not NOP it.

## THE clean fix (next): make TXM selector-38 RECORD a real association (not fake the return)
The op is txm 0x17032b38. Its success path (~0x17032d70) calls the association-record
(0x17031e0c) and returns w24=0; the "outside code limit" checks are `ldr x8,[x20,#0x58];
cmp x8,x23; b.hi err` (0x17032d58) and `ldr x8,[x20,#0x60]; cmp x8,x26; b.lo err` (0x17032d64).
If the GOT region dyld passes is actually correct and only the csobj code-limits are wrong in
this VM (GOTs unmapped), patching those two branches to fall through -> the op RECORDS the given
region as a valid association -> pages validate against it -> no invalid-page kill. Needs a
runtime capture of csobj[0x58]/[0x60] vs region (x23,x26) to confirm before patching. The error
code 42 (0x2a) that floods is a DIFFERENT selector-38 sub-error (not the 0x24 "outside limit"):
find where w24=0x2a is set in 0x17032b38 or its callees (0x17031e0c/0x170480a4/0x17045b10).
Proper end-state fix remains: make the kernel auth-remap actually map the __AUTH GOTs (then
associations are naturally in-range, PAC works without NOPAC, and no bypass is needed).

## Artifacts added
- firmware/txm.assoc_ok  (TXM selector-38 -> success; kills flood but causes invalid-page)
- firmware/bootkc.md0.csoff (nopf4 + AMFI cs_enforcement panic NOP; stalls early -- not useful)
- firmware/txm.orig (pristine TXM backup)
- Boot combo that reaches SpringBoard-spawn: DARWIN_NOPAC=1 + bootkc.md0.nopf4 + firmware/txm
  (flood, slow) OR + firmware/txm.assoc_ok (fast, but SpringBoard invalid-page-killed).

## ############ 2026-09-08 -- iOS 27 FULL BOOT: SpringBoard runs 18s; reboot from 3 crashes ############
Winning combo: DARWIN_NOPAC=1 + bootkc.md0.nopf4 + firmware/txm.sc + rootfs_with_cryptex.dmg
(re-owned to root). Result: the ENTIRE system boots and runs ~37 seconds -- every daemon runs
30-37s (tccd 36.9s, configd 37.3s, wifid 35.7s, backboardd, usermanagerd, ...). SpringBoard
[pid 6] runs for 18.6 SECONDS of real init.

Two fixes were the key beyond the earlier walls:
1. DARWIN_NOPAC=1 -- makes QEMU AUT* strip-only (no FPAC), so daemons stop crashing on the
   unmapped arm64e auth GOTs at load. (Kills the SIGTRAP-at-load crash loop.)
2. firmware/txm.sc -- patch TXM so the selector-38 "associate code region" secure-channel
   check returns allowed. Error 42 was "%s: disallowed due to secure channel constraints"
   (check at txm 0x17033d00, which reads global 0x17088db0 and denies in this SEP-less VM).
   Patch: 0x17033d04 -> mov w0,#1 ; 0x17033d08 -> ret. This kills the TXM flood AND lets the
   associations record so shared-cache pages validate (no OS_REASON_CODESIGNING invalid-page).
   NOTE: the earlier txm.assoc_ok (fake the return) and txm.assoc2 (NOP the code-limit branch)
   were WRONG -- 42 is the secure-channel check, not the code-limit (0x24). txm.sc is correct.

FINAL WALL: SpringBoard exits with SIGTRAP ("sent by exc handler") after ~18s of init -- a
SpringBoard-INTERNAL abort/assertion, not a load-time PAC/CS crash. After 3 such crashes launchd
logs "<Critical>: rebooting due to critical process crashes: SpringBoard" and commits to a
system shutdown/reboot; the VM has no restart mechanism so it ends in
panic "Halt/Restart Timed Out @IOPlatformExpert.cpp:900". SpringBoard's own crash reason is NOT
on the UART serial (it goes to the in-memory unified log), so diagnosing the SIGTRAP needs
either an lldb catch of SpringBoard's userspace trap or extracting its crash report.

## Next steps
- To SEE it: boot with the QEMU window (-display, i.e. run_rootfs.sh without -display none):
    cd /Users/maliosdark/darwin-vm
    DARWIN_NOPAC=1 BOOTKC=firmware/bootkc.md0.nopf4 ROOTFS=firmware/rootfs_with_cryptex.dmg \
      TXM=firmware/txm.sc ./run_rootfs.sh
  (run_rootfs.sh hardcodes -txm "$FW/txm"; either edit it to honor $TXM, or cp txm.sc over txm
  after backing up, or launch qemu directly with -txm firmware/txm.sc.) During SpringBoard's
  ~18s run the DCP framebuffer should show its boot UI before the crash/reboot.
- To stabilise: (a) diagnose SpringBoard's SIGTRAP (lldb: break the userspace exception / read
  its abort; or pull its crash log) and fix the unmet dependency (likely a user-session/persona
  or a display/service assertion); (b) optionally raise launchd's critical-crash reboot
  threshold / prevent the reboot so SpringBoard keeps retrying while iterating.

## Working artifacts (firmware/)
- txm.sc            TXM secure-channel-constraint bypass (selector-38 allowed). USE THIS.
- txm.orig          pristine TXM backup.
- bootkc.md0.nopf4  Wall #2 fix kernel.
- rootfs_with_cryptex.dmg  valid cache (maxSlide reverted) + re-owned to root.
- Boot env: DARWIN_NOPAC=1.

## ############# FINAL DIAGNOSIS 2026-09-08 -- SpringBoard SIGTRAP = DCP/IOMFB RPC is a stub #############
Root of SpringBoard's ~18s SIGTRAP (confirmed by reading qemu-sptm/hw/arm/apple_dcp.c, 378 lines):
the emulated DCP does the AFK transport handshake (INIT/GETBUF/RECV) and paints a static
"bring-up" test frame straight to the loader framebuffer, but it does NOT implement the IOMFB
RPC. On RBEP_RECV (guest posted an IOMFB message) it only prints "guest posted an IOMFB message"
and returns -- it never reads the TX ring, never decodes the IOMFB method, never posts a reply.
So backboardd/SpringBoard's display bring-up RPCs (get display info/timings, register IOSurface,
swap submit -> swap-complete callback, vsync/vblank) get NO replies. Their render setup blocks,
and after ~18s SpringBoard asserts (SIGTRAP). 3 crashes -> launchd "rebooting due to critical
process crashes: SpringBoard" -> Halt/Restart panic (VM has no reset).

So the earlier "we don't need to emulate wifi/speakers/etc. for SpringBoard" holds -- but we DO
need the DISPLAY (DCP/IOMFB) RPC, because SpringBoard actually drives the display and waits on it.

## THE remaining work (development, well-scoped): implement the DCP/IOMFB RPC in apple_dcp.c
On RBEP_RECV: read the guest's message from the AFK TX ring in shared memory (ring at s->bfr_dva),
decode the IOMFB RPC (AFK framing + IOMFB method id + args), and post the expected reply into the
RX ring + signal the guest. Minimum method set to get SpringBoard rendering:
- get display / mode / timings (dimensions 640x1136, refresh) so CoreDisplay/backboardd configure.
- surface registration (IOSurface / layer) so SpringBoard can hand over its framebuffer.
- swap submit -> immediately post a swap-complete callback (and a periodic vsync/vblank) so the
  CoreAnimation render loop advances instead of blocking.
- brightness / power acks (already have a backlight stub).
Reference for the AFK ring + IOMFB protocol: Asahi Linux drivers/gpu/drm/apple/ (afk.c, dcp,
iomfb*). The darwin-vm author left RBEP_RECV as a foothold stub on purpose ("so the next stage
has a foothold"). Once swaps complete, SpringBoard should scan out its real frames to the panel
(software-rendered; no AGX needed) and the home screen should appear.

## Where we are (summary)
SPTM->XNU->secure world -> Image4/SSV/root mount -> launchd -> dyld cache maps -> full userspace:
hundreds of daemons run 30-46s (backboardd, usermanagerd, CommCenter, wifid, locationd, ...),
SpringBoard runs ~18s. Blocked only by the unimplemented DCP/IOMFB display RPC. Winning boot:
DARWIN_NOPAC=1 + bootkc.md0.nopf4 + txm.sc + rootfs_with_cryptex.dmg (root-owned).

## ############## 2026-09-08 (late) -- SpringBoard SIGTRAP root is the DISPLAY (DCP), not IOMFB RPC ##############
Instrumented the DCP (qemu-sptm/hw/arm/apple_dcp.c) and re-ran. Findings overturn the IOMFB-RPC
theory:
- The guest sends the DCP endpoints (0x23/0x24/0x25) ZERO messages -- no AFK INIT/GETBUF/RECV --
  in both 640x1136 and the new 1179x2556 builds. So IOMFB never flows; my RBEP_RECV ring-dump
  never fires. The IOMFB RPC was downstream of the real block.
- The DCP RTKit coprocessor HANDSHAKE never even starts: no "[rtkit:dcp] CPU_CONTROL RUN", no
  "boot -> HELLO" unless forced. The guest's RTBuddy(DCP) driver prints "RTBuddy(DCP): start"
  but never writes the DCP ASC mailbox (CPU_CONTROL/A2I) at all.
- Forcing it via DARWIN_RTKIT_ANNOUNCE=N makes our side send HELLO(min=11,max=12), but the guest
  never reads I2A_RECV / never replies (no HELLO_REPLY -> no EPMAP -> no endpoints -> no AFK).
  Tried N=5 (too early, RTBuddy loads ~14s) and N=20 (guest still silent).
=> The display coprocessor never comes up, so backboardd/SpringBoard get no display surface, and
SpringBoard asserts (SIGTRAP) after ~18s. 3 crashes -> launchd reboot -> Halt/Restart panic.

## Real remaining work: bring up the DCP display coprocessor for iOS 27 (substantial)
The darwin-vm DCP is a minimal stub: it registers the AFK endpoints and CPU-paints a bring-up
console to the loader framebuffer, but the guest's iOS 27 AppleDCP/RTBuddy stack does not engage
it. To get SpringBoard to render:
1. Find why RTBuddy(DCP) never touches the DCP ASC mailbox (power-domain/PMGR gate? firmware-load
   handshake it waits on? IRQ (AIC) not delivered so it never sees our I2A HELLO? register window
   mismatch?). Instrument guest MMIO to the dcp reg window + the DCP AIC IRQ.
2. Complete the RTKit(DCP) mgmt handshake (HELLO<->HELLO_REPLY, EPMAP, STARTEP) so the guest opens
   the endpoints.
3. Then AFK transport + the IOMFB RPC (display-info/timings, IOSurface registration, swap ->
   swap-complete + vsync). Ref: Asahi drivers/gpu/drm/apple (afk.c, dcp, iomfb*), and
   QEMUAppleSilicon/ChefKiss DCP work.
This is a real emulation project (hundreds of lines), the genuine final piece.

## qemu-sptm changes made this session (in darwin-vm/qemu-sptm/hw/arm/, that repo -- not here)
- darwin.c: DARWIN_FB_WIDTH/HEIGHT 640x1136 -> 1179x2556 (iPhone17,3 native; user request).
- apple_dcp.c: on-panel console strings translated ES->EN (STAGE_NAME, panic/console labels);
  RBEP_RECV now hexdumps the AFK TX ring (foothold for the IOMFB RPC once the handshake works).
- Winning userspace boot (display still absent): DARWIN_NOPAC=1 [+ DARWIN_RTKIT_ANNOUNCE=N] +
  bootkc.md0.nopf4 + txm.sc + rootfs_with_cryptex.dmg (root-owned).

## 2026-09-08 -- DCP bring-up narrowed: RTBuddy(DCP) attaches but stays passive
Instrumented the RTKit/DCP path and booted with io=0xffffff (IOKit verbose). Findings:
- The device tree HAS the full display stack (all nodes register): disp0@0, dcp@2E00000 (main
  DCP), dcp@2E00000/AppleASCWrapV6/iop-dcp-nub (RTBuddy attach point), dcpext@6E00000,
  dart-disp0, dart-dcp/AppleT8110DART + mappers, DCPAVSACController. So matching data is present.
- PMGR power domains are emulated (pmgr_write sets PS_ACTUAL=PS_TARGET instantly -> power-on does
  NOT hang). So the block is not PMGR.
- RTBuddy(DCP) ::start() runs (nub allocated, "RTBuddy(DCP): start" prints) but then touches the
  DCP ASC mailbox window ZERO times -- no reads, no writes, no CPU_CONTROL RUN, and it does not
  even poll I2A_CONTROL. rtkit_write logs unconditionally and rtkit_read logs after hello_sent;
  both stay empty for dcp. So RTBuddy is fully passive after start.
- Forcing our side to send HELLO (DARWIN_RTKIT_ANNOUNCE=5/18/20) delivers HELLO(min=11,max=12)
  and raises the DCP AIC IRQ, but the guest never reads I2A_RECV -> no reply -> handshake dead.
- io=0xffffff makes the boot crawl/hang at the IOKit registration phase (~447 lines); not usable.

Interpretation: RTBuddy(DCP) is gated on a bring-up prerequisite BEFORE it will touch the mailbox
-- most likely (a) it wants a DCP firmware image / an ASCWrap boot step it can't complete in the
VM, or (b) the DCP AIC IRQ our HELLO raises is masked/not delivered because RTBuddy has not
armed it yet (it arms it only during a bring-up it never starts). Either way the DCP IOP never
boots -> no RTKit endpoints -> no AFK -> no IOMFB -> no display surface -> SpringBoard SIGTRAPs.

## Concrete next steps for the DCP (the substantial final project)
1. Trace WHY RTBuddy(DCP) stays passive: instrument guest MMIO to the whole dcp@2E00000 window
   AND the AppleASCWrapV6 boot regs (not just the ASC mailbox offsets) + the DCP AIC IRQ
   (mask/enable writes), to see what RTBuddy reads/waits on right after ::start. Consider a
   moderate kext log mask (e.g. RTBuddy/ASCWrap debug) instead of io=0xffffff (which hangs).
2. If it wants a DCP firmware/ASCWrap boot handshake, model the ASCWrap "boot" so RTBuddy
   proceeds to CPU_CONTROL RUN and the RTKit HELLO exchange.
3. Ensure the DCP I2A IRQ is actually delivered (AIC routing) so the guest sees our messages.
4. Then RTKit mgmt handshake -> endpoints -> AFK -> IOMFB (display-info/surface/swap+vsync).
This is a real multi-part emulation effort (the genuine final piece); userspace already boots
fully (SpringBoard runs 18s) with DARWIN_NOPAC=1 + bootkc.md0.nopf4 + txm.sc + root-owned rootfs.

## 2026-09-08 -- Sharpened reboot diagnosis (moderate io=0x484 boot, 1179x2556, EN console)
Booted with a MODERATE IOKit mask (io=0x484, not 0xffffff) so the boot does not hang. Full
userspace comes up; the exact reboot chain is now nailed down from launchd's own log:
- 00:00:45  system/com.apple.logd[78]      SIGTRAP "sent by exc handler", ran 11.0s
- 00:00:51  user/501/com.apple.SpringBoard[7]  SIGTRAP "sent by exc handler", ran 22.7s
- 00:00:54  SpringBoard[88] (respawn)       SIGTRAP, ran 3.2s
- 00:01:00  SpringBoard[89] (respawn)       SIGTRAP, ran 3.3s
- 00:01:00  launchd <Critical>: "rebooting due to critical process crashes: SpringBoard"
- 00:01:58  shutdown WAITING_ON_COALITIONS timeout -> hard reboot ->
            panic "Halt/Restart Timed Out @IOPlatformExpert.cpp:900" (nested).
So the reboot is launchd's 3-strike critical-process crash-loop policy on SpringBoard, NOT a
kernel kill. First instance ran 22.7s (did real init), respawns die in ~3s (hit a now-persistent
condition immediately).

SURVIVORS (reach "running", never crash): com.apple.backboardd[44], driverkitd[56],
iomfb_fdr_loader[76] (the IOMobileFramebuffer FDR/calibration loader), lockdownd, keybagd,
identityservicesd, fairplayd, cameracaptured, etc. So backboardd (the display/render server) does
NOT itself crash -- it is SpringBoard (its client) that aborts.

NEW, IMPORTANT: com.apple.logd ALSO SIGTRAPs (via its own exc handler) at 11s. logd is not a UI
process and needs no display. Two unrelated daemons self-aborting (caught EXC_* -> CrashReporter
-> re-raise SIGTRAP) hints the trigger may be LOWER-LEVEL/shared, not purely "no display surface".
Candidate shared causes to rule in/out: (a) DARWIN_NOPAC side effects on PAC-validating code
paths; (b) a common framework op that asserts when a service/endpoint never answers; (c) genuinely
the display for SpringBoard but logd is an independent second bug.

BLOCKER for root-causing: the crash REASON is not on serial. Userspace os_log goes to logd (dead),
the kernel prints nothing for these (they are caught in-process, not kernel-killed like the earlier
AMFI cases), and the rootfs dmg is mounted READ-ONLY so ReportCrash writes nothing to disk. Need a
guest-side signal: options are (1) enable internal/_PanicOnCrash so the kernel panics WITH the
crashing backtrace on serial (launchd logged: "_PanicOnCrash key: InternalOnly not enabled in the
current environment" for both backboardd and SpringBoard -- so flipping the build to "internal"
would turn a SpringBoard crash into a serial panic w/ backtrace); (2) kernel-gdbstub break on the
EL0 synchronous-exception / exception_triage path filtered to the SpringBoard proc, dump trapframe;
(3) route userspace crash reports off-box. Getting this reason is the gate that decides whether the
remaining work is the DCP display project or a cheaper shared-cause fix.

## 2026-09-08 -- BREAKTHROUGH: the SpringBoard crash is the READ-ONLY ROOTFS, not the DCP
Caught the exact SpringBoard fault with a new QEMU EL0-trap logger and symbolicated it. The
display/DCP is NOT what kills SpringBoard.

### How it was caught (reusable method)
- Added a QEMU hook (env DARWIN_TRAPLOG=1) in qemu-sptm/target/arm/helper.c
  arm_cpu_do_interrupt_aarch64(): logs EL0 BRK/UDEF (the SIGTRAP source) with pc/esr/regs. BRK
  from EL0 is rare (deliberate asserts), so it is quiet. Rebuild: ninja qemu-system-aarch64.
- Boot the winning config with DARWIN_TRAPLOG=1. Result: 4 EL0 BRK traps == the 4 SIGTRAPs
  launchd reported (logd x1 + SpringBoard x3). The 3 SpringBoard crashes ALL trap at the SAME
  shared-cache VA pc=0x1bb2383f0 (brk #0), with x16=0x18f8807a4.
- The VM applies NO dyld-cache slide (slide=0): 0x1bb2383f0 is inside the unslid shared region
  (0x180000000..0x2FCDD8000), so cache VAs map directly. Symbolicate with:
  ipsw dyld a2s <mainDSC> 0x1bb2383f0  (main cache is in
  /private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e).

### The crash
- pc=0x1bb2383f0 = -[BSUIMappedImageCache initWithUniqueIdentifier:options:] + 1140 (BaseBoardUI).
- x16=0x18f8807a4 = __bs_set_crash_log_message (BaseBoard) -- the reason string is set right before
  the brk. Nearby cstrings (subcache .15, base 0x1b8400000) spell out the reason:
    "BSUIMappedImageCache found relative tmpDir=%@ for %@"
    "BSUIMappedImageCache failed to get relative tmpDir from dirhelper for %@ : falling back to
     NSTemporaryDirectory=%@"
    "BSUIMappedImageCache: error mapping CPBitmap data from path=%{public}@ : %{public}@"
  => SpringBoard needs a WRITABLE temp dir to memory-map/copy CPBitmap (compiled image) data. On a
  read-only filesystem the tmpDir/mmap fails and BaseBoardUI aborts (brk) -> SIGTRAP.

### Root cause
darwin-vm boots the ENTIRE rootfs as one READ-ONLY md0 ramdisk with NO writable /private/var data
volume. On a real iPhone /private/var is a separate writable Data partition; here it is part of the
sealed read-only root. Corroborating serial errors on every boot:
  "fixup-mobile-tmp could not create /private/var/mobile/tmp: Read-only file system"
  lockdownd/racoon/mDNSResponder "Failed to bind() a socket: ... error=Read-only file system"
So SpringBoard (and other daemons) simply have nowhere writable. This has NOTHING to do with the
display coprocessor. The DCP work is deferred; SpringBoard cannot even finish BaseBoardUI init
without a writable /var.

### The fix (in progress): give the guest a writable /var
Approach: remount root read-write early (writes go to guest RAM; no host persistence needed).
Ownership lesson learned (important): launchd REJECTS a newly-created LaunchDaemon plist that is
not root:wheel ("Caller specified a plist with bad ownership/permissions"); we cannot sudo/chown in
this environment (no TTY password). BUT an in-place PlistBuddy edit of an EXISTING root:wheel plist
PRESERVES root:wheel even on an `hdiutil attach -owners off` mount (verified: SpringBoard.plist
stayed root:wheel after edit). So repurpose an existing root-owned daemon: we hijacked
/System/Library/LaunchDaemons/bootps.plist (Disabled DHCP server, safe) in place into
Label=com.apple.vphone.rootrw running `/sbin/mount -uw /` at RunAtLoad.
Status: the daemon is now ACCEPTED (root-owned) and spawns, BUT in this restore/ramdisk boot it
lands in the user/501 on-demand-only domain and stalls at xpcproxy (the `/sbin/mount` exec is not
visibly reached; no rw achieved; SpringBoard still crashes 3x -> reboot). Also unconfirmed whether
APFS will even honor an rw remount of this root (cache strings warn "must mount read-write after
revert to unsealed snapshot" / "Remounting read/write is not supported" for some paths).

### Concrete next steps for the writable-/var fix
1. Make the remount actually run as root at load: force the SYSTEM domain (not user/501 on-demand),
   or pick a daemon launchd runs at-load here, or verify `/sbin/mount -uw /` exec + capture its
   stderr on /dev/console (run `/sbin/mount` with no args first to confirm exec + see live flags).
2. If APFS refuses rw remount of the md0 root, use tmpfs overlays (mount_tmpfs exists) on the
   specific writable paths (/private/var/mobile/tmp, /private/var/folders for dirhelper, and the
   BaseBoardUI cache path), or add a second writable data image mounted at /private/var.
3. Most robust / launchd-independent: kernel-patch the rootfs mount to clear MNT_RDONLY (the kernel
   mounts md0s1 at "container_rootmount / handle_mount"), so / is rw from the start.
Once /var is writable, SpringBoard should get past BaseBoardUI init; THEN re-evaluate whether a
display surface (DCP) is the next wall.

### qemu-sptm change this session
- target/arm/helper.c: added DARWIN_TRAPLOG EL0 BRK/UDEF logger in arm_cpu_do_interrupt_aarch64
  (gated on getenv("DARWIN_TRAPLOG"); quiet otherwise). Rebuilt OK.

## 2026-09-08 -- Writable-/var fix attempts: remount is late AND likely ineffective; kernel-mount-time rw is the robust path
Confirmed the fix mechanism and the launchd plumbing, but hit two walls that point to a kernel patch.

### What works
- Repurposed /System/Library/LaunchDaemons/bootps.plist (root:wheel, safe DHCP daemon) IN PLACE
  into Label=com.apple.vphone.rootrw running `/sbin/mount -uw /`. In-place PlistBuddy edits keep
  root:wheel even under `hdiutil attach -owners off`, so launchd accepts it (a freshly-created
  501-owned plist is rejected: "Caller specified a plist with bad ownership/permissions").
- Adding `LimitLoadToSessionType=System` moves it from the on-demand user/501 domain into the
  system domain (verified: log shows "system/com.apple.vphone.rootrw"). `/sbin/mount` then DOES
  exec ("Successfully spawned mount because speculative"), no error printed.

### The two walls
1. TIMING: launchd brings this daemon up only ~52s (speculative), even with KeepAlive=true +
   ThrottleInterval=5. SpringBoard spawns ~31s and crash-loops out by ~46s -- BEFORE the mount.
   logd runs early only because it is a hard dependency of logging; an ordinary LaunchDaemon is
   demanded late here.
2. EFFECTIVENESS: in the one boot where mount ran at 52s, SpringBoard[90] spawned at 54.7s (AFTER
   the mount) and STILL hit the same BSUIMappedImageCache brk. So `mount -uw /` did not actually
   make / writable. The cache strings warn "Remounting read/write is not supported" / "must mount
   read-write after revert to unsealed snapshot": an rw REMOUNT/update of the sealed APFS root is
   refused. An INITIAL rw mount is fine (that is how APFS data volumes mount), so the fix must
   happen at mount time, not as an update.

### Environment facts (constrain the fix)
- The rootfs has NO shell (/bin/sh, bash, zsh all absent) and no /usr/bin/touch or mkdir; only
  /sbin/mount. So a LaunchDaemon can only exec a single binary (no scripting to chain mount+mkdir).
- /private/var/folders EXISTS (empty) -> dirhelper CAN populate /var/folders/<uuid>/T once / is rw
  (this is BSUIMappedImageCache's primary tmpDir path). /private/var/tmp exists (0777).
  /private/var/mobile/tmp does NOT exist (the fixup-mobile-tmp boot task failed to create it at
  15s because / was read-only).
- Reboot policy: launchd ConsecutiveCrashCount 3-strike on the critical SpringBoard
  ("rebooting due to critical process crashes: SpringBoard"; strings: PanicOnConsecutiveCrash,
  ConsecutiveCrashCount, "%hu/%hu").

### THE robust fix (next): make the kernel mount the md0 root READ-WRITE at boot
The kernel mounts md0s1 read-only very early ("container_rootmount: boot from ramdisk /dev/md0" ->
"handle_mount: md0s1 ... flags: 0x1"). If the root is rw from time 0, then fixup-mobile-tmp (15s)
succeeds, dirhelper works, and SpringBoard's BaseBoardUI init finds a writable tmpDir -> no brk.
Plan: locate where MNT_RDONLY is set for the rootfs mount in bootkc (XNU imageboot/vfs_mountroot
path, or the APFS handle_mount flag 0x1) and patch it to mount rw. This is launchd-independent and
races nothing. Fallbacks if APFS still refuses: a separate writable data image mounted at
/private/var, or tmpfs overlays (mount_tmpfs exists) -- both still need an early root exec, so the
kernel patch is preferred.
Note: the DCP/display is NOT on this critical path; it is deferred until SpringBoard survives its
BaseBoardUI init.

## 2026-09-08 (cont.) -- writable-/var: host + runtime routes exhausted; kernel patch is next
Pinned WHY the rootfs is read-only and ruled out the easy routes:
- The RaveSeedD47OS volume has APFS role = System (Sealed: No). APFS mounts a System-role volume
  READ-ONLY at root (ROSV: "apfs mounted RO and is the system volume of a volume group: creating
  the shadow fs_root"). Confirmed via `diskutil info` (Role: System) and the APFS cstrings in
  bootkc.
- HOST role change refused: `diskutil apfs changeVolumeRole disk11s1 D|C` -> error -69599. macOS
  will not reassign the System role on this single-volume container. So we cannot make it a Data
  volume host-side.
- RUNTIME `mount -uw /` refused: it is an r/w UPDATE of a System/sealed volume; APFS strings say
  "non writable nx dev: r/w update not allowed" and "authentication is allowed only on readonly
  mounts". Even when the hijacked daemon (bootps.plist -> com.apple.vphone.rootrw, system domain)
  execs `/sbin/mount -uw /`, a SpringBoard respawn AFTER it still crashes -> the remount does not
  take. Plus launchd only brings an ordinary daemon up ~52s (speculative), after SpringBoard has
  already crash-looped out at ~46s. Timing is unwinnable from userspace.

### The fix: KERNEL patch to mount the md0 root READ-WRITE at boot (initial mount, not an update)
An INITIAL rw mount is allowed (that is how APFS Data volumes mount); only the r/w UPDATE is
refused. So patch the boot-time root mount so APFS does not force RO for this volume. Candidate
sites in the APFS kext (fileset entry com.apple.filesystems.apfs; __TEXT_EXEC.__text base VA
0xfffffff00a843a50, runtime = static + 0x20000000): the ROSV RO-decision (format string VA
0xfffffff007d52e81), apfs_mountroot (str 0xfffffff007d546a3), and the RO-forcing branches for
"unsupported *_readonly_compatible_features -> mount r/o" (0xfffffff007d5fcd9) / "r/w update not
allowed" (0xfffffff007d6f486). Surgical goal: clear MNT_RDONLY / skip the System-volume RO forcing
for the root mount so / mounts rw.
TOOLING NOTE for next session: a naive capstone adrp+add xref scan of the APFS __text found NO
direct refs to these format strings -- APFS uses os_log-style indirect string refs (pointer via
__DATA_CONST / a logging helper), so use ipsw's analyzer (`ipsw kernel disass --fileset-entry
com.apple.filesystems.apfs`) or a proper xref pass, not a quick adrp+add scan. Note the APFS
__text as reported by ipsw starts with a small data table (decodes as udf); real code begins a bit
later (valid prologues seen ~file 0x3840000).

### Alternative if the kernel patch is hard: tmpfs over /private/var/folders
/private/var/folders EXISTS (empty) and is dirhelper's base = BSUIMappedImageCache's PRIMARY
tmpDir. A fresh `mount_tmpfs` there is a NEW mount (not an r/w update, so NOT refused) and needs no
mkdir (mountpoint exists). It still needs an EARLY root exec (same launchd timing problem), so it
is only viable if paired with an early-demanded daemon or a kernel/boot hook. mount_tmpfs exists
in the rootfs; there is NO shell (only /sbin/mount), so daemons can exec one binary each.

### Reusable assets left in place
- rootfs dmg: /System/Library/LaunchDaemons/bootps.plist is hijacked into com.apple.vphone.rootrw
  (`/sbin/mount -uw /`, RunAtLoad, LimitLoadToSessionType=System). Harmless; part of the eventual
  fix once a working writable-/var mechanism lands. (Original bootpd DHCP server is disabled -- fine
  in this VM.)
- qemu-sptm/target/arm/helper.c: DARWIN_TRAPLOG EL0 BRK/UDEF logger (env-gated), for catching any
  future userspace abort and symbolicating it (slide=0; ipsw dyld a2s on the Cryptex main cache).

## 2026-09-08 (cont.) -- kernel-patch RE: APFS RO-mount functions LOCATED (ipsw fixup-aware disasm)
Proven first: SpringBoard is the FIRST daemon to reach "running" (~31s), before every infra daemon
(34-46s). So NO userspace mount daemon can run before SpringBoard's crash -- the kernel patch is
the ONLY fix (not a preference). Host APFS role-change refused (-69599); runtime `mount -uw /`
refused ("r/w update not allowed" for the System-role volume). Volume RaveSeedD47OS = APFS role
System, Sealed:No -> APFS mounts it RO (ROSV) at root.

### Tooling that WORKS (use this, not a raw capstone scan)
APFS log format strings are referenced via fixup-indirected adrp+add that a naive capstone scan
misses. ipsw's analyzer resolves them:
  ipsw macho disass firmware/bootkc.md0.nopf4 -t com.apple.filesystems.apfs \
      -x __TEXT_EXEC.__text --force  > /tmp/apfs_disasm.txt
(one full analysis pass ~2-3 min; then grep the annotated output for the string). Static VA base
0xfffffff008400000; runtime = static + 0x20000000. bootkc is a fileset kernelcache (xnu-13432.2.10
T8140); the big __TEXT_EXEC is VA 0xfffffff008400000 / file off 0x13fc000 / size 0x2f54000.

### Located addresses (static VA)
- container_rootmount: prologue 0xfffffff00a89a870; logs "boot from ramdisk %s" at 0xfffffff00a89a908;
  calls the container mount at 0xfffffff00a88c6a8 with w3=0 (flags arg) right after.
- ROSV RO/shadow-root handler (apfs_vfsop_mount region): logs "ROSV: apfs mounted RO and is the
  system volume of a volume group ... creating the shadow fs_root" at 0xfffffff00a8e09f8; function
  return epilogue ~0xfffffff00a8e09a8-9c8 (retab). Manipulates a mount-flags field at [x19+0x128]
  (clears bit 0x10000, sets 0x40 at 0xfffffff00a8e07f4). Gate at 0xfffffff00a8e08b4:
  ldr x8,[x19,#0xd0]; ldrb w8,[x8,#0x17a]; tbz w8,#0 -> skip ROSV-RO path (candidate: the [obj+0x17a]
  bit 0 is the "volume RO" flag that drives the ROSV path).
- Feature-forced RO (NOT our path): "unsupported apfs_readonly_compatible_features: mount r/o" at
  0xfffffff00a9388c4; "unsupported nx_readonly_compatible_features ... r/w update not allowed" at
  0xfffffff00a88d84c; "non writable nx dev: r/w update not allowed" at 0xfffffff00a88d8b8. Per grok,
  the "r/w update not allowed" paths are a DIFFERENT branch (nx not writable); patching them does
  NOT mount root RW -- do not target them.

### NEXT (pinpoint + patch, then boot-test ~135s)
Find the exact instruction that sets MNT_RDONLY / marks the root mount RO for the System-role md0
volume and neutralize it so / mounts RW at boot (initial rw mount is allowed; only r/w UPDATE is
refused). Two candidate sites: (a) XNU-side root mount flag (simpler if it exists -- disasm
com.apple.kernel __TEXT_EXEC and find vfs_mountroot/imageboot forcing MNT_RDONLY for md0), or
(b) the APFS ROSV gate at 0xfffffff00a8e08b4 (force the [obj+0x17a] bit-0 branch so it does not take
the RO/shadow path) -- but validate this does not skip required mount setup. Prefer (a). Decompile
the mount fn (ipsw -D) or map the struct-mount mnt_flag offset to be certain before patching; a
wrong kernel patch breaks the boot. Do NOT patch BSUIMappedImageCache (grok): once /private/var +
/tmp are RW, SpringBoard stops the brk and should survive BaseBoardUI init.

## 2026-09-09 -- panel render fix: 16-byte stride alignment (flat on-panel console)
The on-panel console skewed diagonally at the 1179-wide framebuffer: 1179*4 = 4716 bytes is not
16-byte aligned, so QEMU's display surface read rows at an aligned stride while apple_dcp wrote at
4716, shifting each row. Fixed by setting DARWIN_FB_WIDTH = 1180 in qemu-sptm/hw/arm/darwin.c
(1180*4 = 4720, 16-byte aligned); 1179 stays the device-native target, the extra pixel is stride
padding. The panel now renders flat and readable. Regenerated the two Spanish-era README panel
screenshots as flat English captures (shots/panel-boot-screen.png = full-OS boot, ring + live
daemon console; shots/panel-root-shell.png = restore-ramdisk Boot A console). The misleading
kernel-panic screenshot (full-os-root-mounted.png) was already removed.

## 2026-09-09 -- lldb runtime BREAKTHROUGH: mnt_flag pinned, but APFS enforces RO at the VOLUME level
Static RE could not pin the RO flag (no kernel symbols; 0x4000/0x4001 appear in many unrelated
contexts). The kernel gdbstub + lldb settled it definitively.

### Method that works (reuse this)
- ipsw whole-section MARKUP disasm of XNU HANGS; `ipsw macho disass <kc> -t com.apple.kernel
  -x __TEXT_EXEC.__text --force --quiet` finishes in ~6 s (2.3M lines) and still resolves adrp
  targets. Use --quiet.
- Boot with `-S -gdb tcp::1234`; the gdbstub port only opens ~90 s in (the 16 GB ramdisk loads
  first), so WAIT for the port before connecting or lldb fails with "Failed to connect port".
- Kernel slide is CONFIRMED 0x20000000 (runtime = static + 0x20000000). Breakpoint at
  apfs_vfsop_mountroot = static 0xfffffff00a8eb380 -> runtime 0xfffffff02a8eb380 hits reliably.
- At that breakpoint x0 = the vfs mount (struct mount); "apfs" appears at mp+0xd4.

### Pinned facts
- struct mount mnt_flag is at OFFSET 0x70.
- At apfs_vfsop_mountroot ENTRY:  mnt_flag = 0x04005001
  (MNT_MULTILABEL|MNT_ROOTFS|MNT_LOCAL|MNT_RDONLY) -- XNU already set MNT_RDONLY before calling.
- AFTER apfs_vfsop_mountroot returns: mnt_flag = 0x1480d001, which EXACTLY matches the
  "rootfs mount flags : 0x1480d001" that libignition prints every boot. So APFS finalises the
  flags (and keeps MNT_RDONLY).

### The decisive negative result
Clearing MNT_RDONLY (bit 0) in mnt_flag at BOTH points was tested:
- cleared at mountroot ENTRY  -> 0x04005000 : writes STILL EROFS (APFS re-set it during mount).
- cleared AFTER mountroot     -> 0x1480d000 : writes STILL EROFS.
In both runs fixup-mobile-tmp still logged "could not set create /private/var/mobile/tmp:
Read-only file system" and SpringBoard still crash-looped to reboot.
=> The vfs mnt_flag is NOT what rejects the writes. APFS enforces read-only at the VOLUME level
(the "!apfs->apfs_readonly" assertions in the write vnops), returning EROFS before VFS's
MNT_RDONLY is ever consulted. Patching/clearing mnt_flag is a dead end; do not retry it.

### Next concrete step
Clear APFS's own volume read-only state, not mnt_flag. Candidate: the APFS mount/volume struct
field at +0x128 whose bit 28 (0x10000000) is returned by the small APFS accessor at static
0xfffffff00a8eb330 (`ldr w8,[x20,#0x128]; ubfx w0,w8,#0x1c,#1; retab`) -- i.e. an "is this volume
read-only" getter. Reach it at runtime from mp (mnt_data / the APFS private data), clear the bit
after mount, and re-test the same way (watch for fixup-mobile-tmp to stop logging "Read-only").
The ROSV path ("apfs mounted RO and is the system volume of a volume group: creating the shadow
fs_root", log at static 0xfffffff00a8e09f8) is what decides this for the System-role volume.
Host-side alternatives remain closed: `diskutil apfs changeVolumeRole` is refused (-69599), and a
Data-volume split needs real restructuring (this rootfs has NO /usr/share/firmlinks, no
/System/Volumes/Data, one System-role volume, and /private/var is a real dir on it).

## 2026-09-09 (cont.) -- APFS volume-RO scan: getter object is NOT a direct field of mp
Re-confirmed mnt_flag = 0x1480d001 after mountroot (stable across boots). Tried to reach APFS's
volume read-only bit by scanning the struct mount (mp, first 0x800 bytes) for a kernel pointer
whose [+0x128] had bit 28 set: NONE found. So the "is-readonly" getter at static
0xfffffff00a8eb330 gets its object at runtime via `bl 0xfffffff00a997154; bl 0xfffffff00a996c64`
(x20 = result), i.e. the object with [+0x128] is derived from mp through those two accessors, not
a direct slot in struct mount.
NEXT: at the mountroot breakpoint, single-step/emulate those two calls (or read mp's apfs private
data pointer -> mnt_data, typically at a fixed struct-mount offset) to get the apfs volume/mount
object, then clear bit 28 of its +0x128 and re-test. Alternatively set a hardware WATCHPOINT on
mnt_flag (mp+0x70) to catch every writer and confirm which code path finalises 0x1480d001, then
target the APFS write-vnop EROFS check (the "!apfs->apfs_readonly" path) directly.

## 2026-09-09 -- ROOT CAUSE FULLY RESOLVED: mnt_flag IS the enforcer, but the root pivots to a RO "shadow fs_root"
The lldb runtime harness settled the whole thing.

### mnt_flag DOES gate writes (earlier "dead end" conclusion was wrong)
Clean binary test: at apfs_vfsop_mountroot, StepOut, clear MNT_RDONLY in the root mount
(mp+0x70: 0x1480d001 -> 0x1480d000), then breakpoint apfs_vnop_mkdir (0xfffffff02a8b6868).
RESULT: apfs_vnop_mkdir WAS REACHED with ZERO "Read-only" serial errors -> VFS allowed the write.
So VFS mnt_flag MNT_RDONLY is exactly the gate; clearing it works.

### Why the earlier clears "failed": the root pivots to a RO shadow fs_root
A hardware watchpoint on the cleared mount's mnt_flag (mp+0x70) fired later at pc
0xfffffff02b34b34c (a memcpy/memset loop) writing 0x1480d000 -> 0x00000000: the ORIGINAL
ramdisk-root mount struct is ZEROED/FREED. Serial confirms "root_pivot_occurred". This is the
APFS ROSV mechanism ("apfs mounted RO and is the system volume of a volume group: creating the
shadow fs_root", log at static 0xfffffff00a8e09f8): the read-only System volume mount is replaced
by a SHADOW fs_root that is ALSO read-only, and fixup-mobile-tmp / dirhelper / SpringBoard's
BaseBoardUI all write to THAT shadow root -> EROFS. Clearing the original mount's mnt_flag is
useless after the pivot.

### The fix (now precisely scoped)
Make the SHADOW fs_root writable, one of:
  (a) clear MNT_RDONLY (bit 0, offset 0x70) on the SHADOW mount, after the pivot -- need to catch
      the shadow mount (created inside the ROSV path via the "setup shadow fs_root" call at
      static 0xfffffff00a90f1c0), or resolve rootvnode->v_mount after the pivot; then a persistent
      kernel patch that clears MNT_RDONLY on that mount, or
  (b) patch the ROSV path so it does NOT create a read-only shadow (the gate at
      0xfffffff00a8e08b4: ldrb w8,[x8,#0x17a]; tbz w8,#0), keeping the original mount, combined
      with clearing MNT_RDONLY at the initial root mount (which is proven to work).
lldb bug to avoid next time: SBWatchpoint has no SetScriptCallbackFunction; use
`watchpoint command add -s python -o '<code>' <id>` via HandleCommand for an auto-continue
re-clear, or a manual continue/re-clear loop.

### Confirmed constants (reuse)
kernel slide 0x20000000; struct mount mnt_flag @ +0x70; apfs_vfsop_mountroot 0xfffffff02a8eb380;
apfs_vnop_mkdir 0xfffffff02a8b6868; ROSV log 0xfffffff00a8e09f8; shadow-root setup 0xfffffff00a90f1c0;
mnt_flag finalizer (XNU) 0xfffffff02acf7248; gdbstub port opens ~90s in; ipsw disass needs --quiet.

## 2026-09-09 -- shadow fs_root RDONLY is set at CREATION (not via vfs_setflags); enforcement helper mis-ID'd
Two more negative results narrow the fix to a single remaining needle:
- Clearing MNT_RDONLY in w8/memory at EVERY vfs_setflags store (0xfffffff02acf7244/48, breakpoint
  callback via SBBreakpoint.SetScriptCallbackFunction, both register-write and memory-write
  variants) did NOT prevent the RO: writes still fail at fixup-mobile-tmp (~line 292 / 21s guest),
  SpringBoard still crash-loops. => the SHADOW fs_root mount gets MNT_RDONLY at mount CREATION
  (a direct mnt_flag init), bypassing vfs_setflags. The vfs_setflags path only builds up the
  ORIGINAL mount's flags.
- 0xfffffff00af58ddc (the helper the 0xaf6c... EROFS cluster calls) is a NAME/PATH validator
  (parses 0xff/0xfe markers), NOT the RDONLY write-reject. That EROFS cluster is not the gate.

### What is proven / where the fix is
PROVEN: mnt_flag MNT_RDONLY (mount+0x70, bit0) IS the write gate. Clearing it on the initial root
mount lets apfs_vnop_mkdir (0xfffffff02a8b6868) be reached with ZERO RO errors. The ONLY reason
writes still fail is the pivot to a read-only SHADOW fs_root (ROSV), whose mnt_flag RDONLY is set
when that mount is allocated.
REMAINING NEEDLE: clear MNT_RDONLY on the SHADOW mount. Options, in order of promise:
  1. Find rootvnode->v_mount AFTER the pivot (or catch the shadow mount at its allocation inside
     the "setup shadow fs_root" call, static 0xfffffff00a90f1c0) and clear mount+0x70 bit0 there.
  2. Static-patch the ROSV gate (0xfffffff00a8e08b4: ldrb w8,[x8,#0x17a]; tbz w8,#0) so no RO
     shadow is created, keeping the original mount, plus clear/patch the initial-mount RDONLY.
  3. Find the actual VFS RDONLY write-reject (mnt_flag & MNT_RDONLY -> EROFS; the small
     vfs_isrdonly-style test was not found by "ldr w0,[x0,#0x70]+and #1+ret", so it is inlined in
     vnode_authorize) and neutralize it -- one patch covers all mounts.

### Confirmed runtime harness (all reusable, all verified this session)
kernel slide 0x20000000; struct mount mnt_flag @ +0x70; apfs_vfsop_mountroot 0xfffffff02a8eb380
(x0=mp); apfs_vnop_mkdir 0xfffffff02a8b6868; vfs_setflags store 0xfffffff02acf7244; mnt_flag
finalizer/zeroer seen at 0xfffffff02b34b34c; ROSV log 0xfffffff00a8e09f8; shadow setup
0xfffffff00a90f1c0. gdbstub port opens ~90s in; ipsw disass MUST use --quiet (markup hangs);
SBWatchpoint has NO SetScriptCallbackFunction but SBBreakpoint does; StepOut works in a script.

---

## Checkpoint: snapshot ruled out, RO is live-fs policy (deterministic static-patch pass)

This pass replaced the flaky runtime lldb "shotgun" with clean, deterministic static
kernel patches on a COPY of the boot kernelcache (firmware/bootkc.md0.rwroot; the working
firmware/bootkc.md0.nopf4 is left untouched), each booted headless and read from the serial log.
Two patches, each on a byte offset confirmed by a unique in-binary signature that also matched
the VA arithmetic (XNU core __TEXT_EXEC base VA 0xfffffff00aa61000 -> file 0x3a5d000):

1. vfs_isrdonly leaf (static 0xfffffff00acf7368): patched `and w0,w8,#0x1` -> `mov w0,#0`
   (file off 0x3cf3370, unique 16-byte signature). Result: NO change. fixup-mobile-tmp still
   logs "could not set create /private/var/mobile/tmp: Read-only file system".
2. apfs_vnop_mkdir internal RO gate (static 0xfffffff00a8b6964): the EROFS(0x1e) at 0xa8b6968 is
   gated by `ldrb w8,[x22,#0x9d]; tst w8,#0xc0; b.eq proceed`. Patched the `b.eq` to an
   unconditional `b` (file off 0x38b2964, `60 01 00 54` -> `0b 00 00 14`). Result: NO change.

### What this proves
- The EROFS on /private/var is NOT produced by the vfs_isrdonly leaf, and NOT by apfs_vnop_mkdir's
  own [node+0x9d] & 0xc0 gate. It is enforced BEFORE apfs runs, at the VFS authorize/lookup layer,
  which reads `mnt_flag & MNT_RDONLY` (mount+0x70, bit0) with INLINE code, not via the leaf.
- Root is NOT mounted from a sealed snapshot. The boot log shows the named-root-snapshot lookup
  FAILING and falling back to the live fs:
    fs_lookup_root_snapshot_name:375  md0s1 failed to get root-snapshot-name from DT
    apfs_find_named_root_snapshot_xid:2153/2191  failed / global payload NULL
    apfs_vfsop_mount:2914  md0s1 failed to find named root snapshot: Need authenticator (81)
    apfs_log_op_with_proc  md0s1 mounting volume RaveSeedD47OS (then mount-complete)
  and the string "Failed to find the root snapshot. Rooting from the live fs of a sealed volume
  is not allowed on a RELEASE build" is present at 0xfffffff00a8e9198. So the volume is the LIVE,
  physically-writable APFS fs (backed by the in-RAM ramdisk), held read-only only by POLICY
  (MNT_RDONLY, "rootfs mount flags: 0x1480d001"), exactly the "needs mount -uw /" situation.
  APFS even carries the intended mechanism: apfs_mount_upgrade_checks (0xfffffff00a8e91a0,
  "can't write-upgrade a snapshot mount"). Our boot never runs a userspace `mount`, so nothing
  upgrades root to RW.
- No Data volume is mounted at all: there is no mount_apfs / fstab / volume-group Data mount in
  the boot. Real iOS keeps /private/var on a separate writable Data volume; our single-dmg boot
  puts /private/var inside the RO system volume, so every /var write fails (fixup-mobile-tmp,
  /var/run/lockdown.sock, mDNSResponder, racoon).
- SpringBoard still spawns (~100+ log lines) and the system still ends in
  "rebooting due to critical process crashes" -> "Halt/Restart Timed Out", i.e. the RO /var wall
  is unchanged by the two apfs-layer patches.

### The one correct lever
Clear MNT_RDONLY (mount+0x70 bit0) on the root mount so ALL enforcement (the 9 inline sites
below + vfs_isrdonly + apfs) sees a writable fs. Because root is the live fs on a RAM-backed
ramdisk, the write physically succeeds and is simply lost on reboot -- acceptable for boot-to-
SpringBoard. This is the in-kernel equivalent of `mount -uw /`.

Nine inline `mnt_flag & MNT_RDONLY` (bit0) test sites in XNU core (runtime = static + 0x20000000):
  0xfffffff00abb95ec  0xfffffff00acd33cc  0xfffffff00acd37d4  0xfffffff00acd8070
  0xfffffff00acd851c  0xfffffff00ace89d0  0xfffffff00acf736c (vfs_isrdonly, already patched)
  0xfffffff00acfa11c  0xfffffff00b02d3ec
The vnode_authorize enforcer is among 0xacd33cc/0xacd37d4/0xacd8070/0xacd851c/0xace89d0.

Next: rather than patch each enforcer (broad + risky), clear bit0 in the root mount at mount
finalize. Find the single mnt_flag store that sets bit0 for the root mount (vfs_mountroot /
apfs live-fs fallback path) and drop the RDONLY bit, or inject a vfs_clearflags(mp, MNT_RDONLY)
after apfs_vfsop_mount succeeds for the root volume. Cut criterion unchanged: fixup-mobile-tmp
without "Read-only file system", then SpringBoard past ~20s without "rebooting due to critical
process crashes".

---

## MILESTONE: root mounted READ-WRITE in-kernel; SpringBoard survival extended 2-3x

The "one correct lever" landed. A deterministic static patch clears MNT_RDONLY on the root
mount at mount time (the in-kernel equivalent of `mount -uw /`), and SpringBoard now runs far
longer before its crash-loop.

### The working patch (firmware/bootkc.md0.rwroot, a COPY; nopf4 left intact)
apfs_vfsop_mountroot (static 0xfffffff00a8eb380, x19=mp) calls its mount worker and, on success
(cbz w0 -> 0xa8eb3f8), runs finalizers with mp still in x19. XNU's mount_common sets MNT_RDONLY
in mnt_flag BEFORE apfs runs, so the clear must happen on this success path. A small stub was
placed in the never-taken-on-success failure-log region and the success entry redirects to it:
  - stub @ file 0x38e73dc (runtime 0xa8eb3dc):
      ldr w8,[x19,#0x70]        ; 68 72 40 b9   (mnt_flag)
      and w8,w8,#0xfffffffe     ; 08 79 1f 12   (clear bit0 = MNT_RDONLY)
      str w8,[x19,#0x70]        ; 68 72 00 b9
      mov x0,x19                ; e0 03 13 aa   (restore the overwritten insn's effect)
      b   0xa8eb3fc             ; 04 00 00 14   (rejoin finalizer path)
  - redirect @ file 0x38e73f8 (runtime 0xa8eb3f8): mov x0,x19 -> `b 0xa8eb3dc` (f9 ff ff 17)
  (Caveat: an actual root-mount FAILURE would now fall into the stub; root never fails in this
  boot, so it is acceptable for the experiment. A clean version would guard the fall-through.)
All offsets confirmed by a unique in-binary signature that also matched VA arithmetic; the
`and` immediate was assembled with keystone (hand-guess `08 7d 00 12` was WRONG; correct is
`08 79 1f 12`).

### Confirmed result
- libignition now reports "rootfs mount flags : 0x1480d000" (was 0x1480d001) => MNT_RDONLY is
  CLEAR. Decoded: NOATIME|MULTILABEL|JOURNALED|DOVOLFS|ROOTFS|LOCAL, no RDONLY, no snapshot.
- SpringBoard survival: BEFORE it crash-looped at ~20-31s guest; NOW it launches, runs services
  ("launching: system support" ... repeated "launching: inefficient"), and each SpringBoard
  instance runs ~3-7.4s; boot reaches 65-91s before "rebooting due to critical process crashes:
  SpringBoard". Crash is SIGTRAP (assertion/trap), sent by the exception handler.

### Remaining wall: /private/var is a SEPARATE mechanism (NOT root MNT_RDONLY)
With root fully RW, exactly 4 writes still fail with "Read-only file system (30)", ALL under
/private/var: fixup-mobile-tmp create /private/var/mobile/tmp, and three /var/run socket binds
(com.apple.mobile.lockdown lockdown.sock, com.apple.racoon vpncontrol.sock,
com.apple.mDNSResponder). Findings:
- Only ONE volume mounts (RaveSeedD47OS = md0s1, System role). No Data volume, no second mount,
  no firmlink log lines. So /private/var lives on the (now-RW) root volume, yet writes still fail.
- Patching apfs_vnop_create's RO gate (0xfffffff00a8c7618 b.eq -> b, file 0x38c3618) AND
  apfs_vnop_mkdir's gate (0xfffffff00a8b6964, file 0x38b2964) had NO effect on these /var writes
  => the /var EROFS is produced BEFORE/OUTSIDE those apfs vnop `[node+0x9d] & 0xc0` gates.
- Leading hypothesis: APFS FIRMLINK redirection. On iOS the System volume firmlinks /private/var
  (and friends) to the Data volume; with no Data volume mounted, /private/var resolves to a
  synthetic/redirected read-only node, so writes EROFS regardless of the root mount being RW.
  Alternative: System-volume-role write protection on the /private/var subtree.
- SpringBoard's own crash reason is not on the serial console (crash reports would be written
  under /var/mobile/Library/Logs, which is exactly what is unwritable). The SIGTRAP is most
  likely the documented BSUIMappedImageCache (BaseBoardUI) needing a writable temp dir under
  /var. Fixing /var should both unblock SpringBoard and let a crash report be written for any
  residual failure.

### Confirmed working patch set in bootkc.md0.rwroot (this milestone)
1. mountroot RDONLY-clear stub (above) -- the load-bearing fix.
2. vfs_isrdonly leaf -> return 0 (file 0x3cf3370) -- proven no-op on its own; harmless.
3. apfs_vnop_mkdir 0x9d/0xc0 gate -> always pass (file 0x38b2964) -- no-op for /var.
4. apfs_vnop_create 0x9d/0xc0 gate -> always pass (file 0x38c3618) -- no-op for /var.
Next: identify the /private/var redirect (firmlink or System-role) and neutralize it, then
re-test the fixup-mobile-tmp line and SpringBoard survival past ~40s.

### /private/var wall: firmlinks RULED OUT too
Forced apfs to mount the live-fs root with firmlinks disabled: patched the firmlink-control
branch in apfs_mount_livefs (0xfffffff00a938a98: `tbnz w8,#0x2,0xa938ae4` -> unconditional `b`,
file 0x3934a98, `68 02 10 37` -> `13 00 00 14`). Boot log now prints
"apfs_mount_livefs:29560: md0 mount no firmlinks" and sets the no-firmlinks flag at mp+0xcd4.
Result: NO change -- fixup-mobile-tmp still EROFS on /private/var/mobile/tmp, still exactly 4
"Read-only file system (30)" (fixup + lockdown.sock + racoon vpncontrol.sock + mDNSResponder),
SpringBoard still SIGTRAPs at ~57s. No new panics (the patch is safe, just not the cause).

### Summary of what the /private/var EROFS is NOT (all ruled out with clean patches)
- NOT root MNT_RDONLY: root is now RW (0x1480d000) and SpringBoard's OTHER writes succeed (it
  runs to ~57-91s), yet only the /private/var paths fail.
- NOT the apfs_vnop_create / apfs_vnop_mkdir `[node+0x9d] & 0xc0` gate (both patched to pass).
- NOT firmlink redirection (mounted with no firmlinks).
- NOT a sealed snapshot (root is the live fs; snapshot auth failed).
The block is PATH-SPECIFIC to /private/var (the paths that are the separate Data volume on real
iOS). Remaining hypotheses, for a fresh session with a working lldb backtrace on the EROFS site:
  a. MACF/Sandbox policy returning EROFS for the restricted system-volume /var subtree (the mount
     carries MNT_MULTILABEL 0x04000000, so MACF is active). Look at mac_vnode_check_create and
     the sandbox/AMFI hooks.
  b. A deeper apfs transaction/purgeable/dataless check for the /var subtree.
  c. /private/var being a distinct read-only entity (a separate unmounted Data volume in the
     md0 container; only RaveSeedD47OS/System mounted). Check whether the dmg container has a
     Data-role volume and, if so, mount it RW at /private/var.
Efficient ground-truth method next time: do NOT break on every vnop over gdbstub (thousands of
hits, far too slow). Instead inject a tiny kernel log patch at the create/mkdir path that prints
the target name + the deciding flag, OR set a single conditional breakpoint keyed on the process,
to capture the ONE backtrace for the fixup-mobile-tmp create.

### Net milestone this session
Load-bearing win: in-kernel `mount -uw /` via the apfs_vfsop_mountroot RDONLY-clear stub. Root is
read-write; SpringBoard now launches and runs services for ~57-91s (was a ~20-31s crash-loop).
The last wall to a live SpringBoard is the path-specific /private/var write block above.
firmware/bootkc.md0.rwroot holds: mountroot RW stub (load-bearing) + vfs_isrdonly=0 + mkdir/create
0x9d-gate passes + no-firmlinks (the latter four are no-ops for /var but harmless). nopf4 intact.

---

## Step A: md0 volume-role inventory (host-side, no boot)

Attached firmware/rootfs_with_cryptex.dmg (16 GB) read-only on the Mac and ran `diskutil apfs
list`. The md0 APFS container has ONE volume only:

  Container disk11  (UUID 3BB25890-5485-4861-BC46-E80E22EC7172), physical store = the dmg
    Volume disk11s1  UUID 629F6C6E-7328-4CFA-9F27-3E5B5C298386
      role   : System (APFS_VOL_ROLE_SYSTEM = 0x0001)
      name   : RaveSeedD47OS (case-sensitive)
      sealed : No
      (vol-uuid matches the boot log "md0s1 vol-uuid: 629F6C6E-...")

  NO Data (0x0040), NO Preboot (0x0010), NO Recovery, NO VM. No sibling volumes.

Filesystem facts on the mounted System volume:
- /private/var is fully populated (var/mobile, var/db, var/run drwxrwxr-x, var/tmp drwxrwxrwx,
  var/folders, etc.). /private/var/mobile exists (drwx--x--x); /private/var/mobile/tmp does NOT
  exist (that is exactly what fixup-mobile-tmp tries to create).
- NO BSD restricted/sunlnk flags and NO com.apple.rootless xattr on /private/var or children
  (only com.apple.provenance). So the /private/var EROFS is NOT a per-file rootless/SIP flag; it
  is APFS's runtime "this is a System-role volume, /private/var belongs to the Data volume of the
  group" enforcement -- and the Data volume is simply absent from the container.
- No /usr/share/firmlinks file on the volume (consistent with the earlier no-firmlinks result).

Conclusion: single System volume, Data missing => Step B (synthesize a Data volume and mount it
RW at /private/var before fixup-mobile-tmp/SpringBoard). The System volume's superblock still
advertises "system volume of a volume group" (the RO boot logged the ROSV shadow-fs-root path),
so APFS expects a Data sibling that is not there. Next: determine whether the darwin-vm kernel
mounts the Data volume of a group itself (ROSV/volume-group path) -- if so, adding a Data volume
to the container with the matching group UUID is enough; otherwise a second ramdisk + kernel_mount
after mountroot, or an early pre-SpringBoard mount, is required. Keeping nopf4 and rwroot as
separate artifacts.

---

## Step B: Data volume synthesized; kernel does NOT auto-mount it (ROSV not firing)

Worked on a clonefile COPY of the dmg (firmware/rootfs_data.dmg; original
rootfs_with_cryptex.dmg untouched). Added a Data-role volume and populated the /var skeleton:
  diskutil apfs addVolume disk11 APFS RaveSeedD47Data -role D   => disk11s2 (role 0x40 Data)
  skeleton on Data root (= /private/var): mobile/tmp, mobile/Library/{Caches,Logs}, mobile/Media,
    db, folders, run, tmp, root  (28 KB used; container had 1.4 GB free, fits).

Empirical boot (nopf4, RO root, rootfs_data.dmg): the kernel mounts ONLY md0s1 (System). It does
NOT mount md0s2 (Data) -- no "mounting volume RaveSeedD47Data" line -- and fixup-mobile-tmp still
EROFS on /private/var/mobile/tmp (RO count unchanged).

Root-cause facts (parsed both APSB volume superblocks directly from the dmg):
- RaveSeedD47OS: role 0x0001 (System), vol_uuid 629f6c6e-..., apfs_volume_group_id = ALL ZEROS.
- RaveSeedD47Data: role 0x0040 (Data), vol_uuid 8bb2833e-..., apfs_volume_group_id = ALL ZEROS.
- APSB layout confirmed against the kernel (apfs_role @ +0x3C4 matches the ROSV code's
  `ldrh w8,[x8,#0x3c4]; cmp #0x40`; apfs_volume_group_id @ +0x3F0; vol_uuid @ +0xF0; volname @ +0x2C0).
- The ROSV "creating the shadow fs_root" path does NOT fire in this boot (RO or RW). Because
  group_id is zero, the kernel never treats RaveSeedD47OS as the system volume OF A GROUP, so the
  ROSV/shadow overlay (which on a real device makes /private/var writable via the Data volume) is
  never engaged. The earlier-session ROSV logs were from a different image/config.

Consequence: the /private/var write block is keyed on apfs_role == System (0x0001) alone, NOT on a
volume group. Synthesizing a Data volume does not help by itself, and neither does pairing via
group_id unless the full grouped-volume structure (matching group_id on both + incompat feature
flags + a container volume-group record) is reconstructed AND the kernel is made to mount/overlay
Data at /private/var. diskutil will not form the group ("No Volume Groups among 2 Volumes").

Viable mechanisms now (pick one; kernel-side preferred per the plan):
1. Kernel-side kernel_mount of md0s2 (Data, already in the container) at /private/var right after
   apfs_vfsop_mountroot succeeds. Deterministic; needs a kernel_mount/vfs mount call, the md0s2
   devvp, and the /private/var mount-point vnode, invoked before fixup-mobile-tmp (~16 s guest).
   This is the concrete form of "Data mounted at /private/var" for THIS kernel (its ROSV/group
   auto-mount does not run).
2. Reconstruct the volume group (set a common non-zero apfs_volume_group_id on both APSBs + fix
   Fletcher-64 checksums + any incompat flags) so the kernel's own group/ROSV path mounts Data.
   Higher risk (blind binary superblock surgery; may need a container volume-group record).
3. Step C: one targeted log at the exact EROFS(0x1e) return that fires for /private/var/mobile/tmp
   (function + vp->v_mount) to pinpoint the role-based enforcer, then neutralize it.

Artifacts kept separate: firmware/bootkc.md0.nopf4 (RO), firmware/bootkc.md0.rwroot (RW stub +
no-op patches), firmware/rootfs_with_cryptex.dmg (original), firmware/rootfs_data.dmg (System +
Data, /var skeleton populated).

---

## Step B breakthrough: volume group synthesized -> kernel ROSV shadow now fires

Formed a real APFS volume group by editing both volume superblocks on the copy (no boot needed),
then validated it host-side and in the guest.

Surgery (firmware/rootfs_data.dmg, on the current/highest-xid APSB of each volume):
- Set apfs_volume_group_id (APSB offset +0x3F0) = 52415645-5345-4544-4437-0000d47da7a0 on BOTH
  RaveSeedD47OS (System, block 0x10050000) and RaveSeedD47Data (Data, block 0x1041d000).
- Recomputed the APFS Fletcher-64 checksum (APSB offset +0x0, over bytes [8:4096]) for each block.
  The algorithm was validated first against the two unmodified APSBs (calc == stored).
- Result host-side: `diskutil apfs listVolumeGroups` now shows
  "Volume Group 52415645-...-0000D47DA7A0" pairing disk11s1 (System) + disk11s2 (Data). So just a
  matching group_id + fixed checksums forms a valid group; no incompat-feature flag was needed.

Guest boot (nopf4, RO, grouped rootfs_data.dmg):
- The kernel ROSV path now FIRES (it did not before the group existed):
    handle_mount:963  md0s1 ROSV: apfs mounted RO and is the system volume of a volume group and
                      mounted as the root fs: creating the shadow fs_root
    fs_setup_shadow_fs_root_tree:3547  md0s1 Created the shadow_fs_root tree <ptr>
- BUT the Data volume (RaveSeedD47Data / md0s2) is still NOT mounted, and fixup-mobile-tmp still
  EROFS on /private/var/mobile/tmp. The shadow fs_root is the RO overlay of the sealed System
  root; it does not by itself mount/stitch Data at /private/var.

Why Data is not mounted -- userspace mount machinery is SKIPPED:
The boot-task sequence (libignition / launchd boot-tasks) shows:
    mount-phase-1        Skipping boot-task
    data-protection      Skipping boot-task
    restore-datapartition Doing boot task -> optional boot task not present
    mount-phase-2        Skipping boot-task
    init-with-data-volume Doing boot task
    fixup-mobile-tmp     ... Read-only file system
The mount-phase-1 / mount-phase-2 tasks are iOS's Data-volume mounter phases (implemented in
/usr/libexec/MobileStorageMounter; the on-demand daemon is
/System/Library/LaunchDaemons/com.apple.mobile.storage_mounter.plist). They are SKIPPED even with
the group present -- almost certainly because rd=md0 puts the boot in a ramdisk/restore mode where
MobileStorageMounter deliberately does not mount the normal data volume. There is no
/private/etc/fstab on the System volume.

Net: /private/var is writable ONLY once the Data volume (md0s2, RW) is mounted/stitched at
/private/var. Remaining levers to make that happen (pick one):
  1. Make MobileStorageMounter run mount-phase-1/2 (find and satisfy the skip condition, or force
     it) so iOS mounts Data itself -- cleanest, pure userspace/config once understood.
  2. Kernel-side kernel_mount of md0s2 at /private/var right after apfs_vfsop_mountroot, before
     fixup-mobile-tmp (~16 s). Deterministic; needs the mount call + md0s2 devvp + /private/var vp.
  3. An early LaunchDaemon (RunAtLoad, ordered before fixup) that runs MobileStorageMounter /
     mount_apfs on md0s2 -> /private/var.

Artifacts (all separate): bootkc.md0.nopf4 (RO), bootkc.md0.rwroot (RW stub), rootfs_with_cryptex.dmg
(original single-System), rootfs_data.dmg (System+Data, group 52415645-..., /var skeleton populated).

---

## Lever 2 (kernel_mount md0s2 at /private/var): feasibility CONFIRMED, blocked on stripped XNU symbols

Per directive, pursued lever 2 (do NOT reverse MobileStorageMounter first; kernel_mount the Data
volume). Prepared base KC firmware/bootkc.md0.datavol = copy of rwroot with the no-firmlinks patch
REVERTED (firmlinks ON) + RW stub kept. Sanity boot (grouped rootfs_data.dmg): ROSV shadow fires,
root RW (0x1480d000), firmlinks on, /var still EROFS -- correct base to add the Data mount.

Mount contract recovered (disasm of com.apple.filesystems.apfs):
- apfs_vfsop_mount(mp=x0, devvp=x1, data=x2, ctx=x3) selects the volume by the DEVICE VNODE
  (devvp = /dev/md0sN), NOT by the mount-args blob (that carries only snapshot selection).
- APFS publishes ONE IOMedia device per container volume ("/dev/%ss%d", M = fs_index+1;
  container_get_dangling_mounts loops volumes 1..100), at container-probe time, independent of
  mounting. So /dev/md0s2 (Data) is VISIBLE to XNU -> lever 2 is NOT impossible by the
  "second slice invisible" criterion. handle_get_dev_by_role @ 0xfffffff00a8fd334 builds
  /dev/<disk>s<idx+1> for a role (Data = 0x40).

Blocker (symbol resolution, not device visibility):
This iOS 27 RELEASE kernelcache is string/symbol-stripped for XNU core. To inject a kernel_mount /
mount_common call I need the VAs of kernel_mount, vnode_lookup, and vfs_context_kernel/current.
- kernel_mount __func__ ("kernel_mount"), vnode_lookup __func__: STRIPPED (not in the binary), so
  no string anchor. nm shows only 611 fileset-export symbols (none of these). ipsw
  `kernel symbolicate` with the blacktop/symbolicator sig DB reports "No valid signatures matched
  kernelcache version" (the DB has kernel/25.0 and 25.6; iOS 27 build 24A5430a is too new) and
  yields only C++ class symbols, not these C functions.
- What IS anchor-findable: namei ("NAMEI_ROOTDIR is set but ni_rootdir is not"), and mount_common
  (its __func__ "mount_common" survives at file 0x6d511 / VA 0xfffffff007071511, referenced by
  adrp/add at 0xfffffff00acd45e4, inside the mount_common body). vfs_context_kernel /
  vfs_context_current strings survive (file 0x4903bf7 / 0x48f395d) but are not yet tied to code.
- Even with mount_common located, calling it needs ~10 constructed args (fstype "apfs", parent+
  mountpoint vnodes for /private/var, componentname, fsmountargs, flags, kernelmount=1, ctx);
  kernel_mount is the wrapper that does the path lookups but is exactly the stripped symbol.

Net: lever 2 as a hand-injection is feasible in principle (md0s2 visible; mount_common found) but
requires resolving kernel_mount + vnode_lookup + vfs_context in a stripped iOS-27 KC via signature
RE, then a large code-cave injection (multi-arg mount call + /dev/md0s2 devvp + timing before
fixup at ~16 s). This is a big, error-prone effort blind; it is dramatically faster/safer with an
iOS-27 symbol source (KDK, a matching symbols.json, or an updated signature set).

Options to proceed (need a decision):
  2a. Provide an iOS-27 symbol source (KDK / symbols.json / updated blacktop sigs) -> resolve
      kernel_mount+vnode_lookup+vfs_context deterministically, then do the injection. Fastest/safest.
  2b. Grind signature-RE to resolve those three from surviving anchors (namei/mount_common as
      anchors + call-graph). Slow, uncertain.
  1'. Revisit lever 1: MobileStorageMounter is a normal userspace Mach-O (full strings/symbols);
      its mount-phase-1/2 skip under rd=md0 may be a simple boot-arg/condition. No kernel symbols
      needed. Deprioritized by directive, but becomes attractive since 2 is symbol-blocked.

Artifacts: bootkc.md0.datavol (rwroot base, firmlinks reverted ON), rootfs_data.dmg (System+Data,
group 52415645-..., /var skeleton), nopf4/rwroot/rootfs_with_cryptex.dmg unchanged.

---

## Lever 1 + userspace helper (2026-09-09): /dev/md0s2 PROVEN to exist; blocker is root privilege

Per directive: parked kernel_mount (stripped symbols), pursued lever 1 (why mount-phase skips) +
a userspace mount helper. Worked on firmware/rootfs_data.dmg (System+Data group) + bootkc.md0.datavol.

Why mount-phase-1/2 skip (from disassembling /sbin/launchd, arm64e, with markup):
- Boot-tasks are launchd-INTERNAL (registered by hardcoded name at 0x1000462e8+; run via
  0x100044ba4 which looks each up in a "Boot" config dict at [0x100087078] = config[+0x688]["Boot"]
  and calls the skip-decision 0x100044c98, then runs it via 0x100044f0c which stats a "Program"
  path -> "optional boot task not present" if missing).
- The skip-decision checks per-task keys: PerformInRestore, LimitLoadFromBootModes,
  LimitLoadToBootingExternalVolume ("Booting non-external volume, skipping boot-task"),
  PerformAfterUserspaceReboot, PerformInBaseSystem. mount-phase is gated to restore / external-
  volume boots; our rd=md0 local ramdisk is neither, so it skips -- effectively "hard-wired off
  for md0", i.e. the "do not fight it, use a helper" case.
- The boot-task "Boot" config source is not an editable on-disk plist (launchd.plist top keys are
  AppExtensions/AppRemovalServices/LaunchDaemons/Symlinks/SystemLibraryTreeState/VersionNumber; no
  "Boot"). So un-skipping mount-phase would require patching launchd, not editing a file.

Userspace helper -- what works and the wall:
- AMFI is NON-ENFORCING in this boot ("AMFI: Launch Constraint Violation (not enforcing)",
  "Booted in a VM"), and launchd ACCEPTS an edited launchd.plist cache despite the stale
  launchd.plist.sig. So the signed cache is not a hard gate here.
- launchd loads a daemon only if BOTH its launchd.plist "LaunchDaemons" cache entry AND the actual
  /System/Library/LaunchDaemons/<x>.plist file exist; the file must be root:wheel or launchd
  rejects it: "Path had bad ownership/permissions (error 122)". Host mounts the dmg noowners
  (everything displays 501:20), and NEW files land 501:20 on-disk -> error 122.
- OWNERSHIP TRICK (no sudo): overwriting an EXISTING root:wheel daemon plist IN PLACE
  (cat mydaemon > existing.plist, truncate-in-place) PRESERVES on-disk root:wheel on the noowners
  mount. Repurposing com.apple.mobile.storage_mounter.plist (file + cache entry) this way made
  launchd accept and SPAWN a custom RunAtLoad daemon (com.apple.datavol-mount) with NO ownership
  error. This is a reusable way to inject a root-owned daemon without sudo.
- The daemon ran `/sbin/mount_apfs /dev/md0s2 /private/var` and got:
      mount_apfs: volume could not be mounted: Operation not permitted   (EPERM)
  EPERM (not ENODEV) => /dev/md0s2 EXISTS and is reachable. **This PROVES the second volume is
  published to XNU as a device** (the requirement before any mount). The mount is refused on
  privilege: in THIS boot EVERY service (SpringBoard, backboardd, our daemon) runs in the
  user/501 domain as uid 501, and mount() requires root (or the MobileStorageMounter mount
  entitlements). POSIXSpawnType System + UserName root made launchd keep the job in the xpcproxy
  trampoline (on-demand) so mount_apfs did not even exec; Adaptive execs it but as 501 -> EPERM.

Net: the helper reaches the exact mount and proves md0s2, but cannot gain root as a general
LaunchDaemon (uid 501 domain), and general daemons run AFTER the boot-task phase (so after
fixup-mobile-tmp at ~16s regardless). Root exists only in launchd's internal boot-task phase and
the kernel. Remaining options: (a) make MobileStorageMounter (which HAS the mount entitlements)
perform the mount -- needs the launchd "Boot" config / a launchd patch; (b) kernel exec-after-
mountroot of the helper (still needs XNU symbols, the parked item); (c) get a boot-task-phase
(root) hook. SpringBoard now runs up to ~10s per instance in some boots but still SIGTRAPs; the
Data mount, when it lands with the pre-populated /private/var skeleton, is the expected unblock.

Artifacts unchanged/clean: bootkc.md0.datavol (rwroot base, firmlinks ON), rootfs_data.dmg
(System+Data group 52415645-..., /var skeleton), nopf4/rwroot/rootfs_with_cryptex.dmg intact.
