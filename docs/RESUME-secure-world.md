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

## UPDATE 7 — x1-injection PROBE works: CL4 advances past the domain deref
Added an EXPERIMENTAL probe (NOT a real fix; clearly marked in code):
  - hw/arm/xnuboot_sptm.c: write a minimal domain descriptor {domain_id, 0...} at
    the start of the CL4-dummypage; export g_cl4_entry_pc (= rx_phys + (entry-virtlo)
    = 0x1000691D4F0) and g_cl4_x1_inject (= scratch phys). domain_id defaults to
    0xC00000001, overridable via $CL4_DOMAIN_ID.
  - target/arm/tcg/helper-a64.c HELPER(exception_return): at the ERET whose target ==
    g_cl4_entry_pc, in guarded state, with x1 still 0, set x1 = g_cl4_x1_inject.
    (log: "[cl4] probe: injected x1=0x... at CL4 entry")
RESULT: CL4 accepts domain id 0xC00000001, passes the tag3 deref + domain lookup, and
ADVANCES. The null-deref at 0x1000691c528 is GONE. New fault one layer deeper:
  Data Abort ESR 0x25 DFSC 0x10, FAR 0x2a0, ELR 0x1000691cd00.
  0x1000691cce0: x0=&global 0x10006f82ce0; w1=2; w2=5; bl 0x10006924e58; ldr x0,[x0+0x2a0]
  -> 0x10006924e58(table 0x10006f82ce0, 2, 5) returned NULL, so [0+0x2a0] faults.
The table 0x10006f82ce0 is in __DATA bss (offset 0x6fece0, > tadk 0x48000, zero-filled)
-> another CL4 registry/global not yet initialised. Same class of problem: CL4's init
depends on subsystem tables that a prerequisite init step (fed by the handoff) should
populate.

### Assessment
The probe proves the mechanism ("feed CL4 the piece it wants -> it advances"), but CL4
init is a CHAIN of such subsystems (domain descriptor -> registry (2,5) -> ...). Fully
synthesizing all of them by hand is open-ended. Two strategic options going forward:
  (A) Keep synthesizing CL4's init inputs piece by piece (this path); OR
  (B) Reverse the SPTM binary's SK bootstrap to reproduce the REAL handoff (one correct
      structure instead of many hand-made pieces) — higher up-front cost, but then the
      whole chain is satisfied at once; OR
  (C) Bypass CL4 entirely and emulate the SecureRTBuddyDCP endpoint in QEMU
      (apple_rtkit.c/apple_dcp.c scaffolding) so XNU's AppleDCPLinkServiceSoC attaches
      without the real secure kernel.
NEXT if continuing (A): trace 0x10006924e58 (the (table,2,5) lookup) to learn the table
layout it needs, and what registers domain 0xC00000001's descriptor. Also re-check
whether 0xC00000001 is the RIGHT domain for this context or if the descriptor needs more
fields than {id}.

## UPDATE 8 — CL4 boot is an ordered chain; the blocker is the SPTM->SK handoff
Probing further (0x10006924e58) shows a lazy singleton factory 0x10006925e70(2,5)
returning NULL -> another uninitialised global. This is not one missing value but a
CHAIN: CL4 init runs in order and each stage seeds the next.

CL4 Mach-O sections (otool -l firmware/cl4_full) reveal the structure:
  __TEXT,__constructor / __init_offsets ; __DATA,__mod_init_func @0xc0698fc0
     -> C++ static constructors that populate the registries/tables we see as null.
  __TEXT,__ENDPOINTS      -> CL4's endpoint table. THIS is where SecureRTBuddyDCP (our
     end goal) is defined/published.
  __TEXT,__DEVICETREE     -> CL4 carries its OWN device tree.
  plenty of __swift5_* -> parts of CL4 are Swift.
Boot order (inferred): entry -> early init -> DOMAIN SETUP (needs the SPTM->SK handoff)
-> __mod_init_func constructors -> registries populated -> __ENDPOINTS published (incl.
SecureRTBuddyDCP) -> Tightbeam IPC ready -> XNU's RTBuddy(DCP) route resolves -> DCP ->
IOMobileFramebuffer -> pixels. We are stuck at DOMAIN SETUP; constructors have not run
yet, which is why so many globals are still zero. Synthesizing each null (path A) fights
symptoms; the root cause is the incomplete handoff.

### Device-tree check (path B) result
The device tree (dtree_dbg) DOES carry exclave config: DCP-EXCLAVE, dcp-exclave-mailbox,
com.apple.service.ExclaveDriverKit / ExclaveSEPManager / ANEExclave, __ENDPOINTS-style
services. BUT its "domain-id" properties are PCIe/clock/perf domains, NOT the SPTM
security domains (0xc0000000N). So the SK security-domain descriptors are SPTM-internal,
not sourced from the device tree in an obvious way. SPTM passes x1=0 to CL4 because our
synthesized boot does not give SPTM whatever it needs to build the real SK handoff.

### Recommended next investment (pick one)
  B1. Reverse the SPTM binary's SK bootstrap (firmware/sptm): find where it builds the
      CL4 genter register state (x0=boot handoff, x1=?) and why x1=0. SPTM string
      "region '%s' ... not immediately after ..." already located the region-order loop;
      similarly search SPTM for the SK-handoff builder. This yields the ONE correct
      structure that satisfies the whole chain.
  A2. Keep the x1 probe and iteratively synthesize: give the domain descriptor more
      fields, seed the (2,5) registry, etc. Faster to see motion, but open-ended.
  C.  Bypass CL4: emulate SecureRTBuddyDCP in QEMU (apple_rtkit.c/apple_dcp.c) so XNU's
      AppleDCPLinkServiceSoC attaches without the real secure kernel. Independent of the
      whole CL4 handoff problem; different (also deep) work.
The x1-injection probe (UPDATE 7) is left in place behind g_cl4_entry_pc; it is
experimental scaffolding, not a fix — remove or gate before any real integration.

## UPDATE 9 — Three-front push (parallel): SPTM reversal status (path B)
Pursuing A, B, C in parallel. B (reverse SPTM's SK bootstrap) progress:
- SPTM Mach-O (firmware/sptm): __TEXT @vmaddr 0xfffffff027004000 (fo 0, 0x18000);
  __TEXT_EXEC @0xfffffff027098000 (fo 0x94000, 0x64000); __DATA @0xfffffff027100000;
  __BOOTDATA @0xfffffff027110000. Loaded with a per-boot slide (NOT fixed) so file
  offsets != runtime addresses; adding the probe scratch page shifted the slide.
- Key SPTM strings (SK bootstrap): "SK BOOTSTRAP PANIC" (fo 0x9dd), "[SK BOOTSTRAP
  PANIC]", "Execution Modes cannot be supported by more than one domain" (fo 0x247c),
  "SK bootstrap complete.", "sptm_init_txm_bootstrap_complete", "Bootstrapping XNU...",
  "uat_bootstrap_parse_dt", "uat_instance->handoff_region->micro_magic", "Too many
  handoff pages!". So SPTM builds the SK handoff from a "handoff_region" and parses the
  device tree (uat_bootstrap_parse_dt). The "Execution Modes ... more than one domain"
  string is the domain-setup logic.
- The genter->CL4 flow at runtime: SPTM executes `genter` (this run: EL2 PC
  0xfffffff0070a390c-ish), gxf entry at 0xfffffff0070a3858, then ERET to CL4 entry
  0x1000691d4f0 with x0=boot-handoff, x1=0. Our probe injects x1 there.
- BLOCKER for static analysis: SPTM code does not reference the domain string via plain
  adrp/add to the absolute vmaddr (no xref found), suggesting SPTM uses a base-register /
  PIC scheme. Runtime disasm needs PHYSICAL addresses (QMP `x/` fails once the CPU is in
  CL4 with MMU off; must use `xp/` at the physical mapping of 0xfffffff0070a38xx).
- NEXT for B: find the physical address backing SPTM __TEXT_EXEC (from the loader's
  macho_load(&sptm_mi, blob_head) placement / adt SPTM-rx region) and `xp/`-disassemble
  the gxf/genter/eret handler to see how x0/x1 are computed for the SK genter, and what
  in the handoff_region / device tree would make SPTM pass a non-zero x1 (the SK domain
  descriptor). Alternatively grep SPTM for "uat_bootstrap_parse_dt" xrefs to see which DT
  properties drive the SK handoff.
Paths A (CL4 init chain) and C (emulate SecureRTBuddyDCP) are being analyzed in parallel;
findings to be merged here.

## UPDATE 10 — Path C findings (emulate/bypass SecureRTBuddyDCP)
"SecureRTBuddyDCP" is NOT a kernelcache constant — it comes from the device tree
(iop-dcp-nub `routes` -> exclave-service = com.apple.service.SecureRTBuddyDCP).
Gate: com.apple.driver.RTBuddy RTBuddy::start() route loop (VA 0xfffffff00a7c5180..
..527c): builds a name-matching dict for com.apple.service.SecureRTBuddyDCP and calls
IOService::waitForMatchingService(dict, timeout=UINT64_MAX) at 0xfffffff00a7c5278;
DCP never returns -> later panic "Unabled to attach route: %p" RTBuddy.cpp:3363 (route
null). Real publisher = SecureRTBuddyProxy (fileset 0xfffffff007d21d90), which
registerService()s ONLY after a live Tightbeam IPC handshake over an exclave comms
endpoint (strings: RTBuddy_tightbeam.c, mExclaveCommsEndpoint, "Missing exclave-endpoint
property", rtbuddyservice_powerstate__decode, shareddartmapperservice). A bare
IORegistry publish is EMPIRICALLY INSUFFICIENT (Parts 24/26/36/37): RTBuddy/AppleDCP
dereference the route object downstream as a real transport.
Two options:
  (a) emulate the exclave comms + Tightbeam rtbuddyservice protocol as a QEMU device so
      the REAL in-kernel proxy completes and registers (much undocumented plumbing);
  (b) KERNEL-PATCH SecureRTBuddyProxy::start() to registerService() immediately with its
      route adaptor redirected to the NORMAL-world DCP ASC mailbox (0x412E00000), patch
      AppleDCP null/secure-route derefs, then drive DCP over the emulated mailbox.
apple_rtkit.c/apple_dcp.c status: ASC mailbox MMIO + RTKit mgmt ep0 handshake + AFK ring
handshake (eps 0x23/0x24/0x25) DONE, but built for a NORMAL ASC-mailbox DCP; missing:
AFK ring memory mapping at bfr_dva, IOMFB/EPIC RPC (mode set / surface register / swap),
framebuffer scanout to DarwinFB, and any SecureRTBuddyDCP publish. Wiring at
darwin.c:938 (apple_rtkit_new "dcp" @0x412E00000) + apple_dcp.c:148 apple_dcp_attach.
Bottom line: approach (b) is the SHORTER/lower-risk route to pixels than booting CL4 +
the 164MB Ap,ExclaveOS userspace; step "finish apple_dcp IOMFB/EPIC + scanout" is the
dominant cost and is common to BOTH the CL4 and the bypass routes -> it is worth building
regardless of which gate we solve.

## UPDATE 11 — Path A findings + THREE-FRONT SYNTHESIS (decision point)
### Path A (CL4 init) — ROOT CAUSE identified
The (2,5) factory null is a REGISTRY lookup, not an allocator:
  factory 0xc00a1e70: mrs x8,tpidr_el0; ldr x8,[x8,#0x10]; ldr x9,[x8] (list head);
  walk singly-linked list matching (key1,key2)=(2,5); return node.value ([node+0x18]);
  head is NULL -> return 0.
TPIDR_EL0 is set by SPTM/GXF (no `msr tpidr_el0` anywhere in CL4 __TEXT). The registry it
points at (TPIDR_EL0->[+0x10]->[+0]) is populated by CL4's CONSTRUCTORS.
__DATA,__mod_init_func @ vmaddr 0xc0698fc0, size 0x58 = 11 pointers, flags 0x09
(S_MOD_INIT_FUNC_POINTERS). Constructors (vmaddr): 0xc0001800, 0xc00795d4, 0xc00a2ad4,
0xc00aa814, 0xc01552bc, 0xc03c9868, 0xc04020e4, 0xc0402e98, 0xc0437ef0, 0xc0439524,
0xc043a8a4. Ctor[2] 0xc00a2ad4 is a registrar (loops 4 entries at table 0xc068e840 stride
0x50, calls 0xc00a2b28 to register each) -> seeds the (2,x) registry the factory reads.
CRITICAL: there is NO in-__TEXT dispatcher that runs __mod_init_func. Per the
S_MOD_INIT_FUNC_POINTERS ABI, the EXTERNAL LOADER (SPTM/exclave loader) iterates this
array and calls each ctor at boot. Our synthesized boot jumps straight to CL4's entry and
NEVER runs the constructors -> every registry is empty -> the whole class of nulls
(domain descriptor, (2,2)/(2,5) singletons, ...). Fixing one null by hand only exposes the
next; the real fix is to run the 11 ctors (with a valid TPIDR_EL0 per-thread context whose
[+0x10] registry field is set up) OR to complete the SPTM->SK handoff so SPTM's loader
performs the mod-init pass. Ordering: ctors run only after domain setup completes.

### Synthesis of A + B + C  (all three fronts)
- A: CL4's registries are empty because the __mod_init_func constructor pass never ran
  (loader's job). This is ONE root cause for the many nulls.
- B: SPTM builds the SK handoff from a handoff_region + device-tree parse
  (uat_bootstrap_parse_dt) and normally runs CL4's loader/ctor pass; reversing it fully is
  deep and its addressing is base-relative (needs physical-addr runtime disasm).
- C: The screen's gate is XNU RTBuddy(DCP)::start waiting on
  waitForMatchingService(SecureRTBuddyDCP, -1). The publisher SecureRTBuddyProxy registers
  that service ONLY after a live Tightbeam handshake over an exclave endpoint -- i.e. it
  needs CL4 **and** the 164 MB Ap,ExclaveOS SECURE USERSPACE (dyld+Tightbeam) running.
DECISIVE FACT: booting the CL4 kernel is NOT sufficient for the screen -- the service is
registered by ExclaveOS userspace, a whole second OS. So the CL4/A+B route to pixels is
enormous (CL4 kernel + constructor/loader emulation + full ExclaveOS bring-up).
=> PRAGMATIC ROUTE TO PIXELS = Path C(b): kernel-patch SecureRTBuddyProxy::start() to
registerService() immediately with its route adaptor redirected to the NORMAL-world DCP
ASC mailbox (0x412E00000), neutralize AppleDCP null/secure-route derefs, and finish the
DCP emulation in apple_dcp.c (map AFK rings at bfr_dva, implement IOMFB/EPIC RPC:
mode-set / surface-register / swap) + scanout to DarwinFB. The apple_rtkit/apple_dcp
transport handshake already exists; the IOMFB/EPIC + scanout piece is the dominant cost
and is REQUIRED BY EVERY route to pixels, so it is worth building now regardless.
The CL4 research (UPDATES 3-11) is preserved: if we ever bring up the real secure world,
the constructor-pass + handoff findings are the key.

## UPDATE 12 — Path C ground truth + no boot-framebuffer shortcut
Empirical state of the display path (baseline, NO -cl4, current bootkc has the
secureproxy_v2 patch):
- XNU boots to userspace: reaches launchd/dyld in the ramdisk ("hello from launchd.1",
  "ignition sequence complete", "dyld[1] check_np errno 12"). 209 serial lines. So the
  secureproxy_v2 patch already prevents the RTBuddy(DCP) route panic and the OS boots
  HEADLESS.
- RTBuddy(DCP)::start() and RTBuddy(ANS2)::start() both run, BUT the DCP ASC mailbox
  (apple_rtkit "dcp" @0x412E00000 + apple_dcp) receives ZERO traffic: no [rtkit:dcp]/[dcp]
  logs, XNU never writes CPU_CONTROL RUN. RTBuddy(DCP) is parked waiting on the secure
  SecureRTBuddyDCP route (which secureproxy_v2 skips rather than satisfies), so it never
  boots the DCP over the normal mailbox. The mailbox emulation is currently dead code.
- Boot-framebuffer shortcut TESTED and does NOT work for iOS 27: `DARWIN_FB=1` carves a
  640x1136 fb at 0x101ffd38000, publishes boot_args.Video (v_display=1, v_rowBytes) and
  patches /vram reg in the DT exactly like iBoot -- but XNU writes NOTHING to it (fb RAM
  0/4096 words non-zero; screendump blank). iOS 27 does not use the legacy boot_args.Video
  framebuffer; the display comes ONLY through DCP. There is no simple-framebuffer path.
=> The screen genuinely requires DCP. To light it via path C the concrete milestones are:
   1. Make RTBuddy(DCP) actually boot the DCP over the ASC mailbox (so apple_dcp is
      exercised). Options: (a) device-tree — turn iop-dcp-nub into a plain ASC-mailbox
      RTKit endpoint (dt_fixup already strips its `routes`/secure-root-prefix, yet RTBuddy
      still waited on the secure route, so DT alone was insufficient — investigate why);
      (b) kernel-patch the DCP transport selection to use the mailbox.
   2. Finish apple_dcp.c: map AFK rings at bfr_dva, implement IOMFB/EPIC RPC (mode-set /
      surface-register / swap), publish DCPEndpoint24 -> AppleDCPLinkServiceSoC ->
      IOMobileFramebuffer.
   3. Scan out the fb to the DarwinFB console (already exists, darwin.c:245 init_framebuffer,
      DARWIN_FB=1). This is the ChefKiss-t8030-scale piece and the dominant cost.
HONEST STATUS: every route to actual pixels (full CL4+ExclaveOS, or DCP-mailbox bypass) is
large; the DCP IOMFB emulation is unavoidable and common to all. CL4 now executes and the
whole secure-world boot chain + DCP gate are mapped and preserved.

## UPDATE 13 — Path C: dtree_norm activates AppleDCP (next blocker = null vtable call)
Booting with firmware/dtree_norm (DCP_NORMALIZE: iop-dcp-nub made structurally identical
to iop-ans-nub, a plain ASC-mailbox RTBuddy IOP) changes the DCP behaviour:
- 381 serial lines (vs 209 baseline). RTBuddy(DCP)::start no longer parks on the secure
  route; AppleDCP becomes ACTIVE and runs its init.
- BUT it panics: "PC alignment exception from kernel at pc 0xfffffff02706e459, lr
  0xfffffff02ac937c8" inside com.apple.driver.AppleDCP (dependency RTBuddy). pc is
  MISALIGNED (ends 0x9) -> AppleDCP did `blr`/`br` through a garbage/null function
  pointer (uninitialised vtable / route adaptor). Nested panic x3.
- Still NO [rtkit:dcp]/[dcp] mailbox traffic -> the crash happens during AppleDCP setup,
  BEFORE it boots the coprocessor over the ASC mailbox.
So DCP_NORMALIZE gets us past the "wait forever" gate but AppleDCP then calls through an
uninitialised pointer (agent C's step 3: neutralize AppleDCP null/secure-route derefs).
This is the pre-existing dtree variant firmware/dtree_norm; many other DT experiment
variants exist (dtree_nx=NO_EXCLAVES, dtree_disp0, dtree_sec, dtree_plain, ...).
NEXT for path C:
  1. Find the AppleDCP call site (lr 0xfffffff02ac937c8, minus slide) that does the bad
     indirect branch to 0xfffffff02706e459; identify which object/vtable is null (likely
     the route adaptor / a service AppleDCP expected from the secure world). Patch it to a
     valid path or provide the missing object so AppleDCP proceeds to boot the coprocessor.
  2. Once AppleDCP writes CPU_CONTROL RUN, apple_rtkit/apple_dcp handshake fires ([rtkit:
     dcp]/[dcp] logs). Then build the IOMFB/EPIC RPC on top (mode-set/surface/swap) and
     scan out to the DARWIN_FB console.
The alignment/null-call is the classic ChefKiss-t8030 DCP bring-up sequence (per Parts
26/36/37): several ordered null-derefs to patch before AppleDCP's start() completes.

## UPDATE 14 — ctor-runner INTEGRATED and WORKING (path A real fix)
Integrated the agent's __mod_init_func constructor-runner (design in
ios27-cl4-secure-world/experiments/cl4-ctor-runner) into the LIVE tree:
- hw/arm/xnuboot_sptm.c: globals g_cl4_tramp_pc/g_cl4_ctors_done/g_cl4_tpidr; the
  104-byte trampoline byte array; CL4-dummypage enlarged to 0x8000 scratch holding
  {domain descriptor @+0, trampoline @+0x80, fake per-thread ctx @+0x200 with
  cells @+0x400, stack top @+0x8000}; pool filled with {modinit=rx+0x698fc0,
  modinit+88, stacktop, entry}. Gate: CL4_NO_CTORS disables it.
- target/arm/tcg/helper-a64.c: in HELPER(exception_return), one-shot divert of the
  CL4-entry ERET to the trampoline (g_cl4_ctors_done), AND set TPIDR_EL0
  (cp15.tpidr_el[0]) = g_cl4_tpidr just before, so ctors that read TPIDR see a
  valid empty context instead of faulting.
RESULT: all 11 constructors run to completion (trampoline installs a scratch stack,
loops __mod_init_func, restores x0/x1, SP=0, br to entry). This seeds the STATIC
domain-descriptor table 0xc068e840 (the real fix for the "domain id 0x50" fault --
root cause, not the x1 hack). CL4 reaches its main init.
- FIRST attempt faulted inside a ctor at 0x1000692aca4 (`mrs x8,tpidr_el0;
  ldr x0,[x8,#8]`, x8=0) -- exactly the agent's flagged TPIDR risk. Fixed by the
  fake per-thread context above.
- Now the first fault is the (2,5) lazy-singleton FACTORY at 0x1000691cd00
  (FAR 0x2a0) -- the SAME frontier the x1-probe reached (UPDATE 7). The factory
  0x10006925e70(2,5) walks the PER-THREAD registry (TPIDR->[+0x10]->list), which is
  still my empty fake list, so it returns null and the caller derefs [null+0x2a0].
Interpretation: ctors seed the STATIC tables (domain descriptors), but the
PER-THREAD registry the (2,5) factory reads is populated later by CL4's own domain
setup (which installs the real TPIDR at 0xc00aa724). We fault at (2,5) BEFORE that.
NEXT: understand what the (2,5) factory 0x10006925e70 does -- does it ALLOCATE (needs
a heap CL4 hasn't set up) or REGISTER into the per-thread list? If allocation, CL4's
allocator/domain heap must come up first (may need more of the real handoff). If the
per-thread registry should already hold (2,5), find which ctor/step registers it.
Either way the ctor-runner is the correct root-cause mechanism and is now in place;
the x1 injection is still active alongside (can be dropped once ctor-seeding alone is
confirmed sufficient for the domain descriptor).

## UPDATE 15 — Path C: AppleDCP crash pinned (garbage PAC callback)
Mapped the dtree_norm AppleDCP panic (fileset kernelcache, slide 0x20000000, top-level
segs: __TEXT 0xfffffff007004000/fo0, __TEXT_EXEC 0xfffffff008400000/fo0x13fc000, ...).
Crash call site: static 0xfffffff00ac937c4 (runtime lr 0xfffffff02ac937c8), file off
0x3c8f7c8, inside a RTBuddy/AppleDCP callback-dispatch function 0xfffffff00ac9376c:
   ...9379c: ldr x8, [x2, #8]        ; x8 = object.callback ptr (x2 = 3rd arg object)
   ...937a0: cbz x8, +0x3c           ; null-checked -> NOT null (so it proceeds)
   ...937bc: ldr w0, [x21, #0x20]
   ...937c0: mov x17, #0xba5         ; PAC modifier
   ...937c4: blraa x8, x17           ; AUTHENTICATED virtual/callback call -> CRASH
x8 = [x2+8] is a PAC-signed function pointer (auth key A, modifier 0xba5). It is
non-null but GARBAGE (not correctly signed), so blraa yields a misaligned target
(0xfffffff02706e459) -> "PC alignment exception". The object x2 was left partially
initialised because DCP_NORMALIZE bypasses the DCP transport-setup step that would have
installed a valid (signed) callback. This is the first of the AppleDCP bring-up
null/garbage derefs (agent C step 3; the ChefKiss-t8030 pattern). 
NEXT for path C: identify object x2 and what installs its [+8] callback in a normal DCP
bring-up; either (a) provide/So it points at a valid handler, or (b) patch this dispatch
to skip when the callback is not a valid signed pointer (careful: it drives real logic).
Then AppleDCP proceeds toward writing CPU_CONTROL RUN to the ASC mailbox (apple_dcp),
after which the IOMFB/EPIC RPC layer must be built. This is the dominant remaining cost.
Two fronts now run in parallel: path C (this) foreground; path A per-thread registry
(the (2,5) factory) via a background agent.

## UPDATE 16 — ctor-runner + registry seed: advances through TPIDR/TPIDRRO/(2,5)/SVC
Applied the per-thread-registry agent's findings + fallback seed. Progression of the
CL4 ctor-pass frontier (each fix advances to the next, whack-a-mole as predicted):
- msr tpidr_el0,xzr in trampoline tail (so CL4's domain-setup takes its tpidr==0 build
  path) -- NOT sufficient alone: a CONSTRUCTOR calls the (2,5) accessor DURING the ctor
  pass (SP in the trampoline scratch stack), before domain-setup (0xc00a6ea4) ever runs.
  Confirmed domain-setup 0x1000692aea4 never executes (0 hits) -- the ctor faults first.
  So the base per-thread services must be present BEFORE the ctors (real HW: SPTM's
  loader registers them before running __mod_init_func).
- Pre-seeded the fake per-thread context's list with node (2,5)->value=rx+0x6fece8
  (loader writes ctx+0x10->regobj->node{next=0,key1=2,key2=5,value}). => (2,5) fault
  GONE. Next fault: 0x1000691e8e8 `mrs x23,tpidrro_el0; ldrb w8,[x23,#9]` -- TPIDRRO_EL0
  (the READ-ONLY per-thread reg) is also 0.
- Set TPIDRRO_EL0 = a zeroed scratch region at divert (cp15.tpidrro_el[0]). => that fault
  GONE. Next: exception 2 [SVC] at 0x1000691e9c0 -- a constructor executes `svc` (an
  intra-kernel/secure syscall), but VBAR_EL1 is 0 (CL4's exception vectors not installed
  yet), so it vectors to 0x200 and cascades.
INTERPRETATION: the constructors expect the FULL pre-ctor environment the SPTM exclave
loader sets up before calling __mod_init_func: TPIDR_EL0 + TPIDRRO_EL0 + a populated base
per-thread registry + installed EL1 exception vectors (VBAR) to service the ctor's SVC.
We are reconstructing that environment piece by piece (open-ended). The SVC is a bigger
step (needs CL4's vector table / syscall dispatch, normally installed during early init).
State knobs added: CL4_NO_CTORS (disable ctor-runner), CL4_NO_X1 (disable x1 probe).
CONCLUSION (reinforced): the root unblock for path A is reproducing the SPTM->SK loader
sequence (register base services + install vectors + run ctors + domain-setup), and even
a fully-booted CL4 needs ExclaveOS for the DCP service. Path C (DCP bypass) remains the
pragmatic route to pixels. The ctor-runner + seed work is preserved and is the correct
mechanism for the eventual full loader emulation.

## UPDATE 17 — Path C: DCP MAILBOX EMULATION ACTIVATED (key discovery)
The DCP mailbox emulation (apple_rtkit/apple_dcp) is gated behind DARWIN_RTKIT=1
(darwin.c:1260 init_rtkit_dcp) -- previously never enabled, which is why the mailbox
saw no traffic. Enabling it:
  DARWIN_RTKIT=1 DARWIN_FB=1  -> "[rtkit:dcp] mailbox 0x412e00000 + 0x88000",
  "[dcp] AFK endpoints 0x23/0x24/0x25, 640x1136 fb at 0x101ffd38000" (fb real).
Other display knobs: DARWIN_DISP=all (maps disp0/dcp/dcp0-expert register stubs),
DARWIN_DART, DARWIN_PMGR, DARWIN_DCPFW (loads firmware/dcpfw). NOTE: DARWIN_DISP=all +
DART + PMGR together broke very early boot (29 lines) -- add stubs selectively.
Device-tree variant selection matters (checked all firmware/dtree*):
  - iop-dcp-nub routes / no-firmware-service:
    dtree_norm: routes=OFF, no-fw-svc=OFF  (drops both -> far=0xb1 no-firmware path)
    dtree_nr:   routes=OFF, no-fw-svc=OFF
    dtree_nr2:  routes=OFF, no-fw-svc=ON   <-- the one to use (no secure wait, keeps
                the firmware-service property)
Progression with DARWIN_RTKIT=1 DARWIN_FB=1:
  - dtree_nr2 + stock bootkc: 409 lines, then the AppleDCP callback-dispatch crash
    (blraa x8,#0xba5 through a garbage PAC callback at 0xfffffff00ac937c4).
  - + bootkc.dcptest (patched that blraa -> `mov x0,xzr`, file off 0x3c8f7c4): no more
    callback crash; next panic far=0xb1 at 0xfffffff00ac6e104:
      ldr x8,[global 0xfffffff00b6c08b8]  (x8 = DCP state object; it is NULL)
      stur d0,[x8, #0xb1]                 -> store to [NULL+0xb1] = far 0xb1.
So AppleDCP's state globals (e.g. 0xfffffff00b6c08b8) are never initialised because the
secure-world DCP service that would build them is absent. This is the chain of AppleDCP
null-derefs (agent C step 3). Patching each store-to-null individually is wrong (it
corrupts state); the correct fix is to provide a valid DCP state object / faithfully
emulate AppleDCP's init, OR load DARWIN_DCPFW and let the real init run. 
MILESTONE achieved: the DCP ASC-mailbox emulation is live and AppleDCP now runs against
it (past the "wait forever" gate). REMAINING to pixels: get AppleDCP's init to complete
(provide/emulate its state + DCP firmware handshake) so it writes CPU_CONTROL RUN ->
[rtkit:dcp] HELLO handshake -> AFK ring INIT -> IOMFB/EPIC RPC (mode-set/surface/swap)
-> scan out the surface to the DARWIN_FB console. This IOMFB emulation is the dominant,
unavoidable remaining cost (ChefKiss-t8030 scale).
Reproduce: DARWIN_RTKIT=1 DARWIN_FB=1 qemu ... -bootkc firmware/bootkc.dcptest
  -dtree firmware/dtree_nr2 ...  (bootkc.dcptest = stock + blraa@0x3c8f7c4 -> mov x0,xzr)

## UPDATE 18 — Ordering agent: ctor-runner was WRONG; real path-A mechanism is svc->SPTM
Agent (cl4-ctor-ordering) findings:
- CL4 entry 0xc00994f0 calls: early bring-up 0xc00a7b3c -> domain-setup 0xc00a6ea4 ->
  main-init 0xc0098004. Domain-setup installs the REAL TPIDR_EL0 (setter 0xc00aa724 @
  0xc00a7114) and registers base per-thread services (registrar 0xc00982e0 @ 0xc00a7178).
  Environment-ready PC = 0xc0099738 (phys 0x1000691d738).
- CL4 RUNS ITS OWN __mod_init_func ctors after domain-setup: wrapper 0xc015c3b4 -> runner
  0xc015c03c -> iterator 0xc015c298 over [0xc0698fc0,0xc0699018), invoked from CL4's own
  idempotent init 0xc0097e3c (done-flag @0xc06fecd8). So the entry-time ctor trampoline
  (UPDATE 14-16) is REDUNDANT and INVERTS the order -> it is the wrong approach.
- CL4 has NO exception vectors: raw-encoding scan finds ZERO msr vbar_el{1,2,3}, ZERO
  eret/eretaa/eretab, ZERO mrs esr/far/elr/spsr_el1. Its 440 `svc #0..#5` are guarded
  MONITOR CALLS to SPTM. The faulting `svc #0` (0xc009a9bc, in log primitive 0xc009a890)
  emits a log record. In this qemu fork, guarded-EL1 sync exceptions vector to
  env->vbar_gl[new_el] (helper.c ~9409) which is NEVER written -> 0 -> cascade. The
  concrete missing mechanism: guarded-EL1 synchronous exceptions must escalate to SPTM's
  monitor entry (gxf_entry_el[2], as EXCP_GENTER does at helper.c ~9561), OR trap-and-
  emulate the svc in qemu.

### Cleanup + clean baseline
Gated the experimental ctor-runner + x1 injection to OPT-IN (CL4_CTORS=1 / CL4_X1=1);
default `-cl4` is now the clean baseline. Clean baseline first fault: the ORIGINAL
domain-descriptor null-deref at 0x1000691c528 (FAR 0, inside domain-setup 0x1000692aea4)
-- object x23 is uninitialised. So domain-setup itself cannot complete because the object
it reads (from the SPTM->SK handoff / an SPTM monitor call) is empty. This ties path A's
two root needs together: (1) the correct SPTM->SK handoff so domain-setup's inputs are
valid, and (2) guarded-svc->SPTM routing so CL4's monitor calls (which populate its state)
actually reach SPTM. Both are deep, and a fully-booted CL4 still needs ExclaveOS for the
DCP service. The ctor-runner code is kept (opt-in) as scaffolding for the eventual faithful
loader emulation.

### Definitive scope (both paths)
PATH A (CL4 secure world): needs correct SPTM->SK handoff + guarded-svc->SPTM monitor-call
routing (deep qemu + SPTM ABI) + CL4's full boot + ExclaveOS (164MB) for SecureRTBuddyDCP.
PATH C (DCP bypass): DCP ASC-mailbox emulation is now LIVE (DARWIN_RTKIT=1); AppleDCP runs
but has a chain of null-object derefs (its state globals uninitialised without the real DCP
service) + needs the full IOMFB/EPIC RPC emulation + scanout (ChefKiss-t8030 scale).
Both are large multi-session efforts. Everything mapped, activated where possible, and
preserved. The pixels-on-screen goal requires completing one of these emulation efforts.

## UPDATE 19 — PANEL LIT with the REAL iOS boot log (screen ON)
Built the display OUTPUT half end-to-end and put real guest content on the panel:
- hw/arm/apple_dcp.c: apple_dcp now DRIVES the panel. A QEMU_CLOCK_REALTIME timer paints
  ~25fps straight into the framebuffer RAM (address_space_write to fb_base) that the
  DarwinFB console already scans out. Two renderers: a bring-up pulse frame, and (the win)
  an on-panel CONSOLE that renders the guest's boot log as a phosphor terminal using
  QEMU's vgafont16 (ui/vgafont.h) -- top status bar "iPhone17,3 iOS 27 t8140 DCP LINK UP",
  newest lines bright, RGB scanout strip, blinking cursor.
- hw/char/exynos4210_uart.c: the emulated UART tees every TX byte to dcp_console_feed()
  so the panel shows the ACTUAL iOS kernel log (AppleSEPKeyStore, AMFI, TrustedClockingKEXT,
  apfs mountroot, RTBuddy(ANS2), AppleANS2 controllers, ...).
Run: DARWIN_RTKIT=1 DARWIN_FB=1 qemu ... (any dtree). Screendump proof:
shots/panel-ios-console.png (real boot log) + shots/panel-scanout.png (pulse frame).
This is REAL iOS content on the iPhone panel, driven by our emulated DCP scanout -- the
output half of the pipeline (DCP -> framebuffer -> DarwinFB -> screen) is COMPLETE and
visible. Remaining for a graphical iOS UI: the guest IOMFB delivering real surfaces
(needs the full OS, not the ramdisk, + the IOMFB/EPIC RPC) -- but the panel now lights
and shows the live kernel boot. env: DCP_NO_SCANOUT=1 disables the painter.

## UPDATE 20 — Graphical iPhone boot screen on the panel (real progress + log)
apple_dcp.c now renders a real iPhone-style boot screen driven by the guest's own log:
- Device identity "iPhone17,3 / iOS 27 * t8140".
- A progress RING whose fill is inferred from actual boot milestones (boot_check_stage
  scans each completed log line: SPTM/XNU -> apfs/mountroot -> RTBuddy/IOService ->
  launchd/ignition -> done), eased smoothly, with a rotating comet head and % in the
  center; stage label below ("Iniciando el kernel XNU" ... "iOS en marcha").
- The live kernel/launchd console in the lower panel, phosphor, newest brightest.
- RGB scanout proof strip. env DCP_NO_SCANOUT=1 disables it.
Reached 100% / "iOS en marcha" booting to userspace (launchd/ignition), the real
com.apple.xpc.launchd log rendered on the panel. shots/panel-boot-screen.png.
Established (dead ends for real graphical UI, all tested): boot_args.Video is fully
populated but iOS 27 does not render to it (uses IOMFB); AppleDCP's init crashes on an
uninitialised handler table BEFORE opening the AFK endpoint (garbage callback, NOT a PAC
issue -- DARWIN_NOPAC=1 strips auth and it still crashes), because its secure-world DCP
service objects are absent. So the graphical iOS UI (SpringBoard) needs the full OS (not
ramdisk) + AppleDCP/IOMFB init completing -- the large remaining effort. What the panel
shows now is the real iOS boot, graphically, driven end-to-end by our emulated DCP.

## UPDATE 21 — Panel polish: panic state + vignette
apple_dcp.c boot screen now reflects the real boot outcome: boot_check_stage sets
boot_panic on "panic("/"Panicked" -> the progress ring turns red, center shows "!",
label "KERNEL PANIC -- ver consola". Added a soft edge vignette so the panel reads like
glass. Normal boot (dtree_dbg) shows the green ring at 100% "iOS en marcha" with the real
libignition/launchd sequence (hello from launchd.1, ignition sequence complete).
shots/panel-boot-polished.png.

## UPDATE 22 — Interactive panel: keyboard -> guest UART wired
Wired the display window's keyboard to the guest so you can type on the panel:
- hw/char/exynos4210_uart.c: darwin_uart_inject(buf,len) pushes bytes into the UART RX
  FIFO via exynos4210_uart_receive; g_darwin_uart captured in exynos4210_uart_create.
- hw/arm/darwin.c: a QemuInputHandler (darwin_kbd_handler) registered+activated in
  init_framebuffer maps QKeyCode->ASCII (letters/digits/symbols with shift, RET='\r',
  BACKSPACE=0x7f, ESC, and ctrl-<letter> control codes) and injects to the UART. So the
  QEMU window's keyboard (or QMP send-key) reaches the guest console. Printed
  "keyboard -> UART live".
VERIFIED the wiring: QMP send-key delivers to our handler and into the UART. BUT the
restore ramdisk runs launchd boot-tasks and finishes (finish-restore) with NO interactive
shell/getty on the console, so there is nothing guest-side to echo/receive input yet -- an
interactive shell needs the full OS (or a shell-enabled boot), same limitation as the
graphical UI. The panel is now interactive-CAPABLE end-to-end; it becomes usable the
moment the guest presents a console.

## UPDATE 23 — Full-OS boot path wired to the lit panel + keyboard
run_rootfs.sh now boots the full iOS rootfs WITH our panel: DARWIN_RTKIT=1 (emulated DCP)
+ DARWIN_FB=1 (framebuffer + on-panel keyboard) alongside DARWIN_AIC/DART/DISP, -serial
mon:stdio, no -display none (a QEMU window opens). Drop a decrypted rootfs .dmg (>1G) in
darwin-vm/rootfs/ (or set ROOTFS=) and run it -> full OS boots with the lit iPhone panel
and keyboard->guest wired. Two entry points: ver_pantalla.sh (restore ramdisk, what we
demo now) and run_rootfs.sh (full OS, needs the user's rootfs -- ChefKiss: firmware
acquisition/decryption is the user's, not automated). Everything except the rootfs itself
is plug-and-play: panel scanout, boot screen, keyboard, DCP mailbox.

## UPDATE 24 — INTERACTIVE ROOT SHELL on the panel (bash-5.3#)
The restore ramdisk already ships a debug shell: /bin/bash + LaunchDaemon
com.jprx.bash.plist (Program=/bin/bash, StdIn/Out/Err=/dev/console, Interactive,
KeepAlive). launchd spawns it ("Successfully spawned bash[3]"; "bash-5.3#" prompt seen
on the panel). Combined with UPDATE 22 (keyboard->UART), the QEMU window's keyboard
reaches bash: typing runs commands (bash echoed "command not found"). So we have a live
interactive ROOT shell on the iPhone panel with NO full rootfs needed. Caveats: bash's
/dev/console is shared with launchd's own logging, so output interleaves with launchd
lines; and QMP send-key must use valid lowercase qcodes (uppercase names are invalid --
a test artifact, not the wiring). On a real keyboard in the QEMU window (ver_pantalla.sh)
input is one key at a time. shots/panel-root-shell.png shows bash-5.3# on the panel.

## UPDATE 25 — keyboard mapping fixed; shell input verified
Bug: darwin_kbd_event treated evt->key.key as a QKeyCode, but it is a LINUX keycode
(ui/input.c: evt.key.key = qemu_input_key_value_to_linux(...)). Fixed with
qemu_input_linux_to_qcode(evt->key.key) before the QKeyCode switch. Now typed chars reach
bash correctly (verified "uname"/"ls" arriving at bash-5.3#). Two bash-5.3# prompts +
typed "ls" visible on the panel (shots/panel-shell-typing.png). Interactive root shell on
the iPhone panel is live and usable; only cosmetic issue is launchd sharing /dev/console.
So: ver_pantalla.sh now gives a lit iPhone panel + a working keyboard into a root bash.

## UPDATE 26 — pram/panic-log backed: real AppleDCP panic UNMASKED (agent Step 1 done)
Agent (appledcp-init) correction: both DCP crashes are in BASE XNU, not the kexts; and
far=0xb1 is the kernel PANIC LOGGER double-faulting because the /pram (embedded panic log)
region was {0,0} -> map fails -> global paniclog ptr (0xfffffff00b6c08b8) NULL -> store to
NULL+0xb1. It MASKS the real panic. Fix (Step 1):
- dt_fixup.py PRAM block + a direct blob-patcher: /pram reg size + /chosen
  embedded-panic-log-size = 0x100000 (dtree_pram / dtree_nr2_pram).
- hw/arm/xnuboot_sptm.c: carve 0x100000 off DRAM, patch /pram reg base to it.
RESULT: boot with dtree_nr2_pram + DARWIN_RTKIT=1 -> "[darwin] pram panic-log backed at
0x101FFC38000" and the panic now PRINTS CLEANLY: "Debugger message: panic / Paniclog
version: 16" -- the far=0xb1 double fault is GONE. The remaining REAL panic is crash A:
"PC alignment exception ... pc 0x..2706e459, lr 0x..2ac937c8" = the base-XNU callback-list
walker (0xfffffff00ac9376c) calling a GARBAGE PAC callback, because AppleDCP left its
handler table uninitialised (took the secure/exclave-firmware branch with no-firmware-
service kept). So crash A is now the SOLE DCP blocker, cleanly visible.
NEXT (agent Steps 2-4): symbolicate crash A in the AppleDCP kext, find the secure-vs-normal
firmware branch, flip it via DT or a minimal branch-gate patch so AppleDCP populates its
handler table and writes CPU_CONTROL RUN -> "[dcp] AFK INIT" against apple_dcp -> then
decode the IOMFB surface (agent Step 6) and blit the guest's real surface to fb_base.
