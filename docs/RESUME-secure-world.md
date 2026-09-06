# RESUME: iOS 27 secure-world (CL4) bring-up in darwin-vm — state & next steps

Self-contained handoff so no knowledge is lost. Full narrative is in
FINDINGS-ios27-display.md (3258 lines). This file is the actionable state.

## Goal
Light the iOS 27 / t8140 (iPhone17,3) display in darwin-vm on an Intel Mac.
Proven blocker: the DCP display coprocessor is gated behind the SECURE WORLD.
RTBuddy(DCP)::start() blocks/panics in `waitForMatchingService(SecureRTBuddyDCP)`
(RTBuddy.cpp:3363 `panic("Unabled to attach route: 0")`). That service exists
only if the SK (Secure Kernel = exclaves) domain is running. So: boot the SK.

## What works NOW (all opt-in behind `-cl4`; baseline `run.sh` -> root shell, verified)
- iOS 27 boots to root shell on Intel (`./run.sh`).
- darwin-vm loads Apple's exclave SECURE KERNEL and SPTM bootstraps the SK domain
  and TRANSFERS execution into it. The CL4 secure kernel EXECUTES at EL1.
- It faults early (PC=0x200) because its chained pointers are not yet slid.

## Secure-world components (extracted this session)
- `firmware/exclavecore` — 32MB DNUB bundle (exclavecore_bundle.t8140.RELEASE.im4p
  unwrapped). Parse with `parse_exclavecore.py`. TOC (24-byte entries: tag u32,
  offset u64, size u64, type u32; TOC starts at file 0x284):
    txtk 0x18000/0x68c000  = SECURE KERNEL (Mach-O arm64e, __TEXT@0xc0000000, entry 0xc00994f0)
    txtr, txtu, tadk/r/u, knlr/knlu (metadata), tsru 0x1d20000/0x1a8000 = exclave trustcache
- `firmware/exclave_comp/txtk` — the extracted secure kernel (load with `-cl4`).
- ExclaveOS dmg (`exclave/.../decrypted/094-14052-182.dmg`) = secure userspace
  (System/ExclaveKit: dyld, Tightbeam IPC, secure frameworks). Not needed to boot SK.

## darwin-vm code changes made (in ios27-display-bringup.patch)
- `-cl4 <file>` option: qemu-options.hx, system/vl.c (QEMU_OPTION_cl4),
  darwin.c (MACHINE_CLASS_ARG(cl4) + property registration + open into info->cl4_f).
- `include/xnu/boot/xnuboot.h`: added `char *cl4; mmap_file_t cl4_f;`.
- `hw/arm/xnuboot_sptm.c`: CL4 loader. Computes `cl4_mi` (guarded on
  info->cl4_f.buf). PHASE 1 (after BootKC-rs, before DeviceTree):
  PUSH_SEG(cl4,"__TEXT") -> CL4-rx; set_adt_mmap empty CL4-ro; CL4-virt=virtlo;
  CL4-entry=entrypoint. PHASE 2 (after BootKC-le, before CL4-dummypage):
  PUSH_SEG(cl4,"__DATA")->CL4-rw; PUSH_SEG(cl4,"__LINKEDIT")->CL4-le.
  `bytes_before_sptm` includes `(have_cl4 ? cl4_mi.virthi-cl4_mi.virtlo : 0)`.
- `hw/arm/apple_regs.c`: CL4 presence via `info->cl4_f.buf != NULL` (NOT a
  device-tree probe — that asserts on missing region and broke baseline).
  CTRR-C lower = CL4-rx (else DeviceTree). CTXR-B = [CL4-rx,CL4-rx] (else CL4-dummypage).

## The panic chain conquered (each fix advanced SPTM; read panics via QMP)
SPTM does not print to serial. Read its panic from memory: attach QMP
(`-qmp unix:/tmp/x.sock,server,nowait`), after the WFE hang dump the assembled
panic string (near `0xfffffff0..106184`, shifted by SPTM's relocation). Use
lldb via `-s` gdb stub for system regs (ESR_EL1/FAR_EL1/SCTLR_EL1/VBAR_EL1).
Slide runtime->static for SPTM = +0x20000000.
1. `validate_region_order: DeviceTree not immediately after CL4-ro` -> split CL4
   phase1(rx/ro)/phase2(rw/le). FIXED.
2. `ACC-CTRR-C mismatch` -> CTRR-C lower = CL4-rx. FIXED.
3. `ACC-CTXR-B mismatch` -> CTXR-B = CL4-rx region. FIXED.
After all three: SPTM enters CL4. PSTATE EL2t->EL1h, registers hold CL4 physical
addrs, CL4-rx[0]=0xfeedfacf. CL4 runs, calls __bzero_chk (0xc015b210), then
branches to raw 0x200 (unslid chained pointer). SCTLR_EL1=0 (MMU OFF),
VBAR_EL1 set, ESR_EL1=0 (direct branch, not a trap).

## THE CURRENT FRONTIER: slide CL4's chained pointers
CL4 (txtk) uses DYLD chained fixups; `__TEXT.__thread_starts` is EMPTY (size 0),
`__TEXT.__chain_fixups` @file 0x669b30 size 0x80 holds them. Parsed:
  header: version=0, starts_offset=0x20, imports_count=0 (ALL rebases, no binds)
  starts_in_image: seg_count=5; only seg[1] has chains:
    ptr_format=12 (DYLD_CHAINED_PTR_ARM64E_USERLAND24), page_size=0x4000,
    seg_offset=0x68c000 (__DATA), page_count=18, 17 pages have chains.
CL4's entry (0xc00994f0) is position-independent (adrp), builds a key-value
handoff array at 0xc06ff3f0 from x0/x1 (SPTM's args), then calls init. It expects
its DATA chained pointers ALREADY SLID. Since CL4 runs MMU-OFF at its physical
load base when it dereferences them, they must be slid to the PHYSICAL base.

### Next step (implement): pre-slide CL4 chained pointers in the loader
In xnuboot_sptm.c after PUSH_SEG(cl4,"__DATA"), walk seg[1]'s chains and rebase.
For ptr_format=12 (ARM64E_USERLAND24), each 8-byte slot:
  - if bit63 (auth): { target:32 (offset from base), diversity:16, addrDiv:1,
    key:2, next:11, auth:1 } -> new = base + target  (drop PAC bits; QEMU may
    have PAC off, or set signed pointer — try plain rebase first)
  - else (rebase): { target:36? , high8:8, next:11, bind:1, auth:1 } — for
    USERLAND24 the unauth rebase target is `target` (low bits) + (high8<<...);
    canonical: unpackTarget = (raw & 0xFFFFFFFFFF) then runtimeOffset. USE the
    exact dyld_chained_ptr_arm64e_rebase24 bitfields from mach-o/fixup-chains.h.
  - `next` (11 bits) * stride(8) steps to the next pointer in the page; next==0 ends.
  page_start[pi] gives the first pointer offset in page pi (0xFFFF = no chain).
Base to use: CL4 physical load address = phys of CL4-rx (printed as
"[cl4] phase1 rx phys 0x...", e.g. 0x10006884000). Rebase target is relative to
CL4's vmaddr base 0xc0000000, so: new_ptr = cl4_phys_base + (target_vmaddr - 0xc0000000)
where target_vmaddr = 0xc0000000 + chained_offset  =>  new_ptr = cl4_phys_base + chained_offset.
ALTERNATIVE if physical-slide fails at MMU turn-on: SPTM has
SPTM_FUNCTIONID_SLIDE_REGION / register_core_file_region driven by
header->kernelSlide — register CL4 as a slidable core-file region instead.

### Test after implementing
Boot with `-cl4 firmware/exclave_comp/txtk -dtree firmware/dtree_dbg` (SPTM_DEBUG
tree sets chosen/debug-enabled=1). QMP-sample PC: if it leaves 0x200 and CL4
progresses (or a NEW panic string appears), the slide worked. Keep chasing
panics via the QMP buffer read until CL4 finishes SK bootstrap and
`SecureRTBuddyDCP` registers; then RTBuddy(DCP) route attaches, DCPEndpoint24
publishes, AppleDCPLinkServiceSoC binds, IOMobileFramebuffer -> pixels.

## Reusable techniques
- Guest shell: scratchpad/guestsh.py (socket serial, trickle input ~6ms/char).
- ioreg / class census from inside iOS: fbprobe.c, arm64e ncurses stub.
- Kernel patches: capstone/keystone, semantic anchors, NOP/asm helpers; SPTM
  accepts a patched kernelcache (no integrity check here).
- dt_fixup.py env: EXTRA_NODES (un-mute by path), DCP_REGION, SPTM_DEBUG, NO_EXCLAVES.
- Machine env switches: DARWIN_AIC/PMGR/DART/RTKIT/ASC/ANSFW/DCPFW, DARWIN_RTKIT_ANNOUNCE.

## Patchers (kernel, in darwin-vm/, each reproduces a documented result)
patch_rtbuddy_secureproxy_v2.py (verified-safe null guard, IN bootkc now),
patch_rtbuddy_route.py / _route_timeout.py / _route_skip.py / _route_skip0.py
(all cascade to panics — see FINDINGS Parts 32-39; the real fix is the secure world).
firmware/bootkc = silence_logs + secureproxy_v2. firmware/bootkc.prepatch = clean baseline.

## CRITICAL CORRECTION (found after Part 44): __DATA was garbage
The `txtk` component is 0x68c000 bytes = ONLY __TEXT. The CL4 Mach-O's __DATA
(fileoff 0x68c000, filesize 0x48000) is BEYOND the txtk file, so
PUSH_SEG(cl4,"__DATA") read garbage -> the "unslid 0x200 pointer" was actually
garbage __DATA. The real __DATA is the **tadk** component (0x48000 = exact
__DATA filesize). DNUB naming: txt*=text segs, tad*=data segs, paired k/r/u
(txtk+tadk = the kernel image). VERIFIED: tadk's chained pointers decode to
valid CL4 vmaddrs (chain starts __DATA+0x8, stride next*8, target = offset from
0xc0000000; auth and non-auth both present, imports_count=0 so all rebases).

### The real fix (do this): reconstruct the full CL4 Mach-O, then apply fixups
1. Build a contiguous CL4 macho file: [0:0x68c000]=txtk(__TEXT),
   [0x68c000:0x6d4000]=tadk(__DATA), [0x6d4000:...]=__LINKEDIT (filesize 0x12970;
   component unknown — zero-fill first, boot likely doesn't need symbols).
   The macho load commands already point at these fileoffs.
2. Load with -cl4 <reconstructed>. Now PUSH_SEG(__DATA) gets real chained data.
3. Apply chained fixups to __DATA (parse __TEXT.__chain_fixups @file 0x669b30):
   for each slot new = BASE + target_field. BASE = CL4 physical load addr while
   MMU off (or 0xc0000000 vmaddr if CL4 runs MMU-on — TEST physical first since
   observed SCTLR_EL1=0). Decoder (ptr_fmt 12): auth=(raw>>63)&1,
   next=(raw>>51)&0x7ff, target = auth? (raw&0xffffffff) : (raw&0x7ffffffffff).
   next*8 = bytes to next slot; next==0 ends chain. page_start[] per 0x4000 page,
   0xFFFF=no chain. Maybe SPTM slides it itself once real chained __DATA is present
   — try WITHOUT pre-slide first, then WITH.

## UPDATE 2: cl4_full built; SPTM does NOT auto-slide; pre-slide needed
Reconstructed `firmware/cl4_full` = txtk(__TEXT) + tadk(__DATA) + zero __LINKEDIT
(build script inline in session; segs __TEXT@fo0/0x68c000, __DATA@fo0x68c000/
0x48000, __LINKEDIT@fo0x6d4000/0x12970). Loaded with -cl4 cl4_full: still
PC=0x200 EL1h -> SPTM does not slide CL4's __DATA. Must PRE-SLIDE in the loader.
COMPLICATION: CL4 is split (CL4-rx/__TEXT phase1, CL4-rw/__DATA phase2) so the
two segments are NON-CONTIGUOUS in physical, and CL4 runs MMU-off (SCTLR_EL1=0)
using __DATA pointers -> rebase must be PER-SEGMENT to physical:
  target_offset < 0x68c000  -> new = rx_phys  + target_offset            (__TEXT)
  0x68c000..0x6d4000        -> new = rw_phys  + (target_offset-0x68c000)  (__DATA)
  >= 0x6d4000               -> new = le_phys  + (target_offset-0x6d4000)  (__LINKEDIT)
rx_phys/rw_phys/le_phys are the blob addresses where each PUSH_SEG landed.
Chain: __TEXT.__chain_fixups @file 0x669b30; seg[1]=__DATA, page_size 0x4000,
page_start[] per page (0xFFFF=none), first slot __DATA+0x8, next*8 stride.
Decode ptr_fmt12: auth=(v>>63)&1,next=(v>>51)&0x7ff,target=auth?(v&0xffffffff):(v&0x7ffffffffff).
Write new 8-byte value = rebased address (drop auth/next bits). If MMU-off phys
rebase still faults after CL4 enables its MMU, switch to vmaddr rebase
(0xc0000000+target) AND ensure SPTM maps CL4 (CL4 may expect MMU-on entry).

## UPDATE 3 — BREAKTHROUGH: CL4 NOW EXECUTES (thousands of instructions)
The physical per-segment rebase WAS correct, but three QEMU-side bugs stopped CL4
from running past its first SIMD instruction. All three are now fixed and CL4
boots deep into its own initialisation. This is the single most important update.

### Root cause of the old "stuck at PC=0x200" symptom
PC=0x200 EL1h with VBAR_EL1 nonzero was NOT an exception vector — it was the tail
of a fault cascade. Traced with `-d int` (logs every taken exception + ESR/ELR/FAR):
  1. exception 30 [genter]  : SPTM (EL2) genters and ERETs to EL1 PC 0x1000691d4f0
     (= rx_phys 0x10006884000 + entry offset 0x994f0). CONFIRMS SPTM enters CL4 at
     the macho entrypoint, MMU OFF (SCTLR_EL1=0), running on PHYSICAL rebased ptrs.
  2. exception 1 [Undefined] : ESR 0x1fe00000 => EC 0x07 = "Advanced SIMD/FP access
     trapped". ELR = 0x100069dc230 = `ldr q0,[x0],#0x10` (a SIMD memcmp/memcpy).
     CL4 used a Q register but CPACR_EL1.FPEN was 0.
  3. exception 3 [Prefetch Abort] loop at 0x200 : the FP trap jumped to VBAR+0x200,
     that handler faulted too, cascading until VBAR became 0 -> PC 0x200 -> inst
     abort -> 0x200 forever. THAT is the "stuck at 0x200".

### The THREE QEMU fixes (all keyed on the guarded domain: env->currentg == 1)
Apple's GXF hands the guarded world (SPTM/TXM + the SK/exclave kernel "CL4") a
context that HW sets up (FP on, Normal memory) but which this qemu-sptm fork did
not emulate. CPACR_EL1 is NOT GXF-banked here (no cpacr_gl[]) and the SK genters
before XNU programs CPACR, so CL4 inherited CPACR=0. Fixes:

  A. target/arm/helper.c  fp_exception_el(): at top of body, if (env->currentg)
     return 0;  // guarded domain: FP/SIMD always accessible. Kills the EC 0x07 trap.

  B. target/arm/ptw.c  get_phys_addr_disabled(): in the `if (r_el == 1)` block,
     change `if (hcr & HCR_DC)` to `if ((hcr & HCR_DC) || env->currentg)` so
     MMU-off guarded data accesses get memattr 0xff (Normal WB) instead of 0x00
     (Device nGnRnE). Mirrors HCR_EL2.DC default-cacheable early-boot behaviour.

  C. target/arm/tcg/hflags.c  aprofile_require_alignment(): after the SCTLR.A
     check, add `if (env->currentg) return false;`. Without this the TRANSLATOR
     bakes ALIGN_MEM into CL4's TBs (because MMU off + no DC => "Device => require
     alignment"), so an unaligned `ldr q1,[x1]` still faulted even after fix B made
     the runtime page Normal. Fix B alone is not enough — alignment is decided at
     translate time. Both B and C are required.

  (An earlier attempt set CPACR in the EXCP_GENTER handler; it did NOT stick — the
   correct single point is fp_exception_el via currentg. That hack was reverted.)

### Fault progression after each fix (all via `-d int`, first non-genter excp)
  before A : EC 0x07 FP trap @ 0x100069dc230 (ldr q0)
  after  A : EC 0x25 data abort, DFSC 0x21 ALIGNMENT, FAR 0x10006884933 @
             0x100069dc234 (ldr q1,[x1] unaligned, memcmp of the same routine)
  after B  : SAME alignment fault (proves runtime-Normal is not enough)
  after B+C: NO fault through the whole memcmp; CL4 runs from 0x100069dc234 all the
             way to 0x1000691ece0 -> exception 7 [Breakpoint] EC 0x3c = `brk #1`.

### CURRENT FRONTIER: brk #1 assertion @ 0x1000691ece0 (file off 0x9ace0)
Disasm: a chain of 4 calls, each `bl <fn>; tbnz w0,#0,<ok>`; the 4th falls through
`tbz w0,#0, 0x1000691ece0(brk #1)`. Args: x0=x19 (an object), x1=0x10006f79788.
Guest memory at 0x10006f79788 is a DOMAIN-NAME string table:
  "...AIN_ID\0" "SPTM_DOMAIN\0" "XNU_DOMAIN\0" "TXM_DOMAIN\0" "SK_DOMAIN\0"
  "XNU_HIB_DOMAIN\0" ...
So CL4 is matching x19 against the SPTM security domains and asserting when none
match (domain lookup/registration). The four match fns: 0x100069233c8, 0x10006923a24,
0x10006924080, 0x100069246dc. Next step: understand what domain/config CL4 expects
from the SPTM->SK handoff (boot-args block CL4 builds at entry: it stored tags
0x15,0x1a,0x2,0x3 into an array @vmaddr 0xc06ff3f0 in the entrypoint code) and why
the match returns 0 — likely the handoff/config table (possibly in __DATA bss that
is zero-filled, or expected from a boot structure we don't provide) is empty.

### How to reproduce / debug (commands)
Boot (serial to file, int log):
  qemu-system-aarch64 -M darwin -bootkc firmware/bootkc -dtree firmware/dtree_dbg \
    -tc firmware/ramdisk.tc -ramdisk firmware/ramdisk.dmg -sptm firmware/sptm \
    -txm firmware/txm -cl4 firmware/cl4_full -args "rd=md0 serial=3 -v ..." \
    -nographic -serial file:/tmp/cl4.out -d int -D /tmp/int.log -m 8G
First real fault: `grep -n "Taking exception" /tmp/int.log | grep -v genter | head`.
Ordered exec trace (filter to CL4 + low addrs, small log):
  -d exec,nochain -dfilter 0x0..0x1000,0x10006884000..0x10006f10000 -accel tcg,one-insn-per-tb=on
CPU regs at a PC: add `,cpu` to -d and `-dfilter <pc>..<pc+4>`; last block prints X0..X30.
NOTE: lldb software breakpoints in the CL4 physical range are UNRELIABLE on this
gdb stub (never hit) — use `-d int` / `-dfilter` exec traces instead.
Disasm CL4 by file offset (offset = phys - 0x10006884000) on firmware/exclave_comp/txtk
via capstone (.venv has it).

## UPDATE 4 — brk #1 characterised: bad "domain id" 0x50 from an object graph
Registers at brk (via `-d exec,cpu -dfilter 0x1000691ec80..0x1000691ece4`):
  X19=0x50  X20=3  X08=0xc00000001  X01=0x10006f79788(domain-name table)
  X29=0x10006f5b890  X30=0x1000691ecc4  SP=0x10006f5b880
Function 0x1000691eba0 = "domain descriptor lookup": x19=x0(arg); ~14 calls, each
`mov x0,x19; bl <fn>; tbnz w0,#0, 0x1000691ecc8(ok)`; fall-through -> brk #1.
Each <fn> is `mov x8,#<id>; cmp x0,x8; b.ne fail; <fill descriptor at x1>`. Example
fn 0x100069246dc checks id 0xc00000001 (= 1 | (0xc<<32)) and, on match, writes a
descriptor into [x1] (pacia-signed fn ptrs at +0x40/+0x48/... ). So the valid domain
ids look like 0xc0000000N. x19 arrived as 0x50 -> not a domain -> assert.
Caller (return 0x1000692afb4): call site 0x1000692afb0 `bl 0x1000691eba0`. x0 there
comes from an object graph: x23 = ret of 0x1000691e008; then
  0x1000692afa0 ldr x0,[x23+8]; cbnz x0, skip;  else ldr x0,[x23+0x18]; bl 0x1000691c528
so the "domain id" is a field of the object returned by 0x1000691e008 (or derived via
0x1000691c528). It reads 0x50 instead of 0xc0000000N.
HYPOTHESIS: the object graph / config CL4 walks here is fed by the SPTM->SK handoff
that we do not supply (or by __DATA bss / __LINKEDIT which are ZERO in cl4_full).
0x50 is not a plausible-but-off domain id, so the structure is likely uninitialised.
NEXT STEPS to try:
  1. Dump the object at x23 (ret of 0x1000691e008) and 0x1000691e008 itself — find
     which global/handoff it reads; see if that global is zero (uninitialised).
  2. Check the CL4 entrypoint boot-info array it builds at vmaddr 0xc06ff3f0 (tags
     0x15,0x1a,0x2,0x3 with values x9=adr, x0, x1) — this is the SPTM->SK handoff
     CL4 expects; we may need to populate a real handoff (domain table) there.
  3. Consider providing __LINKEDIT (currently zeroed) — reconstruct from the real
     linkedit if the lookup reads relocated/linkedit-backed data.
  4. As a research shortcut to keep moving: patch CL4 to accept id 0x50 (or make the
     lookup return a valid domain) ONLY to see the NEXT stage — but the real fix is
     feeding CL4 the correct domain handoff.
STATUS: CL4 now boots from entry through full early init + a large SIMD memcmp and
into domain registration. The "won't execute" barrier is BROKEN. Remaining work is
feeding CL4 the correct SPTM->SK handoff so its domain graph is valid.

## UPDATE 5 — __DATA made physically CONTIGUOUS; domain lookup now passes
Root of the 0x50 "bad domain id": CL4 runs MMU-off and reaches its own __DATA via
PC-relative `adrp` (e.g. entry `adrp x1,0xc068c000`), which with MMU off lands at
rx_phys + 0x68c000 = 0x10006F10000 (the CONTIGUOUS position). The split layout put
__DATA far away (0x100076CC000), so CL4 read whatever sat at 0x10006F10000 (the
DeviceTree region) as __DATA -> garbage domain id 0x50.

FIX (hw/arm/xnuboot_sptm.c): load CL4 __TEXT + __DATA + __LINKEDIT CONTIGUOUSLY in
phase 1 and cover __DATA+__LINKEDIT with the CL4-ro region (so region order stays
CL4-rx, CL4-ro, DeviceTree and SPTM's validate_region_order is satisfied). Phase 2
only registers CL4-rw / CL4-le descriptors pointing back into that block (no second
push). Rebase is now uniform: new = rx_phys + target_offset. Loader prints
"[cl4] contiguous rx .. rw 0x10006F10000 le 0x10006F98000 ..".
RESULT: the domain-descriptor lookup (0x1000691eba0) now SUCCEEDS. CL4 advances past
it. (validate_region_order did NOT complain — the extra pre-DeviceTree page lives
inside the DeviceTree region, so CL4-ro end == DeviceTree start.)

### New frontier: null field in a CL4 __DATA-bss global
Next fault (`-d int`): Data Abort, ESR 0x25 DFSC 0x10 (external abort), FAR 0x0,
ELR 0x1000691c528 = tiny accessor `ldr x0,[x0]; ret` called with x0=0 (deref of
physical 0 with MMU off -> external abort). Caller 0x1000692afa8:
  mov x23, x0(ret of 0x1000691e008); ldr x0,[x23+8]; cbnz x0,skip;
  ldr x0,[x23+0x18]; bl 0x1000691c528(deref)
x23 = 0x10006f83808 = rx+0x6ff808 -> that is offset 0x73808 into __DATA, i.e. in the
ZERO-FILLED bss part (tadk filesize is only 0x48000). So x23 is a CL4 global at
0x10006f83000 whose fields [+8] and [+0x18] are still 0 -> not yet initialised.
0x1000691e008 itself writes to 0x10006f83900 (adrp 0x10006f83000+0x900) and returns
a pointer into this global area. So CL4 init has not populated this global; likely a
constructor/registration step that needs an input we don't yet provide (handoff at
x0=0x10006ff4370 has segment addrs at +0x20/+0x28/+0x30 = rx/rw/le and 0x10006f10000
at +0x18/+0x38). NEXT: trace 0x1000691e008 fully to see what it reads to build the
global, and what should have set [x23+8]/[x23+0x18]. This is CL4 runtime init, one
layer past domain registration.

## UPDATE 6 — null deref pinned to MISSING boot-info tags 1 and 3
The CL4 entrypoint builds a boot-info array of {tag,value} 16-byte entries at
vmaddr 0xc06ff3f0 (= phys rx+0x6ff3f0 = 0x10006f833f0) from the registers SPTM
passes at genter:
  {0x15, 0}                        (hardcoded)
  {0x1a, 0x1000691d4f0}            (hardcoded = CL4 entry)
  {0x2,  <tag2 handoff ptr>}       (= x0 at entry; the SK handoff struct)
  {0x3,  0}                        (= x1 at entry; SPTM passed x1 = 0)
Parser 0x1000691e008 scatters each entry's value into a global config struct at
0x10006f83000 via a jump table (0x1000691e2bc, indexed by tag-1). Decoded tag->field:
  tag 1 -> +0x810   tag 2 -> +0x818   tag 3 -> +0x820   tag 0x15 -> +0x0b8
  tag 0x1a -> +0x8e8  (…full map in session notes; tags 7,8,9,0xc,0xe..0x2d used)
The faulting caller (0x1000692af9c..afb0):
  x23 = &global+0x808;  x0 = [x23+8]  (= field 0x810 = tag 1);  cbnz x0, domain_lookup
  else x0 = [x23+0x18]  (= field 0x820 = tag 3);  bl 0x1000691c528 (ldr x0,[x0])
Field 0x810 (tag 1) = 0 because the entrypoint never emits tag 1. Field 0x820
(tag 3) = 0 because SPTM passed x1 = 0. Both null -> ldr x0,[0] -> external abort
(FAR 0, MMU-off phys 0). CL4 expects tag 1 (and/or tag 3) to be a valid pointer.

tag2 handoff dump @0x10007090370 (contiguous run):
  +0x00 0x10000000000  +0x08 0x200000000  +0x10 0x10016adc000
  +0x18 0x10006f10000(=__DATA)  +0x20 0x10006884000(=__TEXT)  +0x28 0x10006f10000
  +0x30 0x10006f98000(=__LINKEDIT)  +0x38 0x10006fac000(end)  +0x40 0x53e78
  +0x48 0x10007090bcc   (rest ZERO)
So the handoff carries CL4's segment map but NOT whatever tag 1 / tag 3 should
point at (a domain descriptor / boot manifest). This is the SPTM->SK handoff being
incomplete for our synthesized boot.

### ACTIONABLE next steps
  1. Identify what tag 1 and tag 3 point to on real HW (what struct CL4 derefs at
     [x23+8]/[x23+0x18] after the cbnz). Disassemble the domain_lookup path
     (0x1000691eba0 onward) and the code after 0x1000691c528's caller to see how the
     pointer is consumed -> reveals the expected struct layout.
  2. Find where SPTM sources x0/x1 for the SK genter (reverse the SPTM binary's SK
     bootstrap) OR synthesize a valid tag1/tag3 structure in guest memory and make
     the loader/handoff point CL4 at it.
  3. Simplest experiment to advance one more step: allocate a small zeroed struct,
     set tag 3's value (SPTM x1, or patch the boot-info array post-build) to point at
     it, and see what field CL4 derefs next -> iteratively learn the struct.
STATUS: CL4 boots through entry, early init, SIMD memcmp, handoff parse, and domain
descriptor lookup; blocks on the SPTM->SK handoff missing tag1/tag3. Every fix this
session moved CL4 strictly forward. The remaining work is reconstructing the SK
handoff, not fighting the CPU/loader anymore.
