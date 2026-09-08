# darwin-vm iOS 27 boot -- LIVE STATE (read this first)

One-screen "where are we / what's been tried" so we never re-litigate settled points.
Last updated: 2026-09-07.

Target: iOS 27 (iPhone17,3 / t8140 / d47ap, build 24A5430a) under jprx/darwin-vm +
qemu-sptm on an Intel Mac. Goal: reach SpringBoard.

## Boot chain status
- [x] SPTM -> XNU -> secure world (CL4)
- [x] Image4/nonce without SEP        (DVM-1 magazine stubs)
- [x] SSV seal / root-hash-auth        (DVM-3, DVM-4)
- [x] bsd_init FSIOC_KERNEL_ROOTAUTH   (DVM-5 gate NOP)
- [x] APFS root mounts (RaveSeedD47OS), launchd (PID 1) execs
- [x] dyld shared cache MAPS           (maxSlide=0; Wall #2 crossed)
- [x] libSystem loads (no more "Library not loaded")
- [x] launchd survives + dyld cache MAPS + full userspace (bootkc.md0.nopf4; Wall #2 crossed)
- [x] daemons launch (rootfs re-owned to root; launchd bootstraps hundreds of daemons)
- [ ] daemons RUN their code  <-- FINAL WALL: TXM selector-38 association fails (auth GOTs unmapped; nopf4 skipped the auth-remap)
- [ ] SpringBoard

## Current wall (CONFIRMED root cause) -- REFRAMED 2026-09-07
NOTE: check_np's errno 12 is NORMAL (dyld's pre-map call; region legitimately
empty, sr_first_mapping==-1). The REAL failure is dyld's
`shared_region_map_and_slide_2_np` syscall -> `vm_shared_region_map_file_setup`
mapping loop: its `vm_map_enter_mem_object_control` into the nested shared submap
never sets `sr_first_mapping` (map fails, likely a whole-span/permanent+immutable
occupant blocks the FIXED placement). Target THAT, not check_np.
sr_first_mapping source = vm_shared_region.c:1946 (= sms_address - sr_base_address).

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
