# Goal 3 build plan: guest pixels via the DCP / IOMFB coprocessor

Status: goal 3 is the open frontier. This document records the full protocol
blueprint, the exact current blocker (localized on the full-OS boot), and the
staged roadmap to a first guest-rendered frame. Goals 1 and 2 are done; see
STATE_darwinvm_boot.md.

## Why there is no shortcut on t8140

Confirmed empirically and by research (Asahi, eShard, and the local first-hand
FINDINGS-ios27-display.md in darwin-vm):

- There is NO linear / simple-framebuffer path on iOS 27 / t8140. Populating
  boot_args.Video + the /vram DT node + display-scale leaves the framebuffer
  100 percent zero. Verified again this session: with the qemu DCP boot-log
  painter disabled (DCP_NO_SCANOUT=1) a screendump of the console surface is
  pure black. XNU on t8140 does not render a legacy boot console; every display
  kext is a -DCP variant (AppleMobileDispH17P-DCP, IOMobileGraphicsFamily-DCP,
  EXDisplayPipeH17P). The simple-framebuffer trick works only on Apple Silicon
  Macs (m1n1 keeps iBoot's surface live) and on pre-DCP iPhones (A13 and older,
  directly programmable display pipe). t8140 has a Display CoProcessor (DCP).
- The only route to guest pixels is to speak the DCP protocol: an RTKit
  coprocessor whose IOMFB endpoint runs a private shared-memory RPC, ending in
  swap_submit surface descriptors that point at DART-mapped, compressed guest
  surfaces. Nobody has emulated an A14+ DCP publicly.

## Current blocker (localized this session, on the full OS boot)

New ground vs the FINDINGS restore-ramdisk work: with goals 1 and 2 done we now
boot the full OS, and RTBuddy(DCP) actually instantiates (serial: "RTBuddy(DCP):
start()"), which it never did in the restore ramdisk (RTBuddy = 0 instances
there). But:

- RTBuddy(DCP) does ZERO MMIO to the DCP ASC mailbox (our apple_rtkit maps it at
  reg[0] = 0x412E00000 + 0x88000, which FINDINGS confirms is correct; the write
  trace budget logged nothing).
- Sending HELLO proactively (DARWIN_RTKIT_ANNOUNCE) gets NO response from the
  guest: it is not listening on the mailbox yet.
- Running with -d unimp shows the guest touches no unimplemented display MMIO at
  all.

Conclusion: RTBuddy blocks in software BEFORE the mailbox stage, waiting on the
DCP firmware being delivered and the coprocessor being brought up (power via
PMGR, firmware load into DCP SRAM, then CPU_CONTROL RUN, then it waits for the
coprocessor HELLO). The userspace IOMFB_FDR_Loader also runs then exits(1). So
the immediate engineering target is the firmware-delivery / coprocessor-boot
path, not yet the mailbox RPC. This matches FINDINGS Part 6: "emulate the
ASC/RTBuddy v6 mailbox and load t8140dcp_restore.im4p as the coprocessor
firmware, the way iBoot does".

## The protocol blueprint (reference: AsahiLinux drivers/gpu/drm/apple + soc/apple)

Cached source under the session scratchpad dcp/. iOS/t8140 is a firmware tier
beyond Asahi's v12_3 / v13_5: exact struct offsets and the A-method / D-callback
opcode numbers WILL differ and are unknown for iOS 27; treat 13.x as the closest
reference and confirm each by capturing real traffic.

Layer stack (bottom to top):

1. ASC mailbox (Linux drivers/soc/apple/mailbox.c). Two 64-bit words per message:
   msg0 = payload, msg1 = endpoint (low 8 bits). Registers: CPU_CONTROL 0x044
   (RUN = bit 4), A2I_SEND0 0x800 / SEND1 0x808, I2A_RECV0 0x830 / RECV1 0x838,
   control/empty/full bits. Writing CPU_CONTROL RUN boots the coprocessor.

2. RTKit management, endpoint 0x00. Type field = msg bits [59:52].
   HELLO=1, HELLO_REPLY=2, STARTEP=5, SET_IOP_PWR_STATE=6/ACK=7, EPMAP=8,
   SET_AP_PWR_STATE=0xb. HELLO min/max ver in [15:0]/[31:16]; supported 11..12.
   EPMAP: bitmap [31:0], base [34:32], LAST bit 51. STARTEP: ep in [39:32].
   Boot handshake the coprocessor side drives: send HELLO -> AP HELLO_REPLY ->
   send EPMAP(bitmaps) -> AP EPMAP_REPLY -> AP STARTEP per endpoint. Standard
   endpoints auto-started: crashlog 1, syslog 2, debug 3, ioreport 4, oslog 8.
   App endpoints from 0x20. Buffer-request messages carry an IOVA to allocate.

3. Endpoint map (Asahi macOS numbering; iOS differs, see note):
   SYSTEM 0x20, DISP0/iBoot 0x23, DCPEXPERT 0x22, DPAVSERV 0x28, AV 0x29,
   DPTX 0x2a, IOMFB 0x37. iOS/t8140 exposes the main IOMFB path as
   "DCPEndpoint24" = endpoint 0x24 (from the local FINDINGS Part 16); our
   apple_dcp.c already uses 0x24/0x25/0x23, which matches iOS, not macOS 0x37.

4. AFK ring transport (drivers/gpu/drm/apple/afk.c), for the EPIC endpoints.
   Mailbox RBEP type in [63:48]: INIT 0x80/ACK 0xa0, GETBUF 0x89/ACK 0xa1,
   INIT_TX 0x8a, INIT_RX 0x8b, START 0xa3/ACK 0x86, SEND 0xa2, RECV 0x85,
   SHUTDOWN 0xc0/ACK 0xc1. BLOCK_SHIFT = 6 (sizes/offsets are in 64-byte blocks).
   Ring header (192 bytes) at buffer_base + base: bufsz @0x00, rptr @0x40,
   wptr @0x80, data area @0xC0. Per message: afk_qe 16 bytes at data+rptr:
   magic 0x20504F49 ("IOP ") @0x00, size @0x04 (bytes), channel @0x08,
   type @0x0C, payload @0x10. Advance rptr = ALIGN(rptr + 16 + size, 64).

5. EPIC packet inside afk_qe.data: epic_hdr 16 bytes (version=2 @0x00, seq @0x01,
   timestamp @0x08) then epic_sub_hdr 24 bytes (length @0x00, version=4 @0x04,
   category @0x05, type/stype @0x06, tag @0x10, inline_len @0x14). epic_type:
   NOTIFY 0, COMMAND 3, REPLY 4, NOTIFY_ACK 8. category: REPORT 0, NOTIFY 0x10,
   REPLY 0x20, COMMAND 0x30. subtype: ANNOUNCE 0x30, TEARDOWN 0x32,
   STD_SERVICE 0xc0. Commands use epic_cmd (retcode, rxbuf/txbuf DVAs, lengths)
   with the real args in the tx/rx DMA buffers (epic_service_call, 64-byte
   header, magic 0x69706378 "xcpi", data @0x40).

6. IOMFB endpoint (macOS 0x37 / iOS DCPEndpoint24). NOT AFK. One 1 MiB coherent
   shmem region whose DVA is handed over once (SET_SHMEM, type 0, dva in [63:16],
   flag 4). Messages on the endpoint: type in [3:0] = SET_SHMEM 0, INITIALIZED 1,
   MSG 2. MSG carries length [63:32], offset [31:16], context [11:8], ACK bit 6.
   Context ids: CB 0, CMD 2, ASYNC 3, OOBCB 4, OOBCMD 6, OOBASYNC 7. Windows:
   tx CMD 0x00000 / OOBCMD 0x08000; rx ASYNC 0x40000, OOBASYNC 0x48000, CB
   0x60000, OOBCB 0x68000. Packet header 12 bytes: tag[4] (byte-reversed
   fourcc), in_len @0x04, out_len @0x08, in-data @0x0C. Methods are "Axxx"
   fourccs (AP to coproc), callbacks "Dxxx" (coproc to AP); numbers are version
   dependent. Key: swap_start A407, swap_submit A408, set_power_state A472/A468,
   set_display_device A410. Callbacks: D000 did_boot, D120 boot_1, D589
   swap_complete, D451 allocate_buffer, D201 map_piodma, D452 map_physical.

7. Swap and surface. swap_submit (A408) payload = dcp_swap (swap_id @0x50,
   surf_ids[4] @0x54, src_rect[4] @0x64, dst_rect[4] @0xC4, swap_enabled @0x104,
   bg_color @0x10C) + dcp_surface[4] (format fourcc, stride, width, height,
   buf_size, surface_id, plane_info, compression_info) + surf_iova[4] (the
   surface DVAs). The 13.2+ layout adds surf2[5]/surf2_iova[5] and grows the
   surface padding 7 -> 47. Pixel formats are DCP fourccs (BGRA = 'ARGB', etc).
   Surfaces on this SoC are COMPRESSED (Apple's lossless AGX/DCP compression);
   eShard escaped this on A13 by spoofing an older chip-id, which is not
   available on t8140.

8. DART translation. Every surface address in swap_submit, the shmem DVA, and
   RTKit buffer IOVAs are DVAs, not physical: they require DART page-table
   translation. Two contexts: the main DCP DART and a piodma DART (driven via
   the D201 map_piodma / D452 map_physical callbacks). Our current dart-dcp
   model does not translate (reads DVAs as raw physical), which must be fixed
   before any real surface can be located.

## Staged roadmap (each stage independently testable)

Stage A. Coprocessor boot / firmware delivery (CURRENT BLOCKER).
  Get RTBuddy(DCP) to actually bring up the coprocessor so it drives the ASC
  mailbox. Investigate the RTBuddyFirmwareService chain: ensure t8140dcp.im4p /
  t8140dcp_restore.im4p is where RTBuddy expects it, and model enough of the
  coprocessor power/firmware handshake (PMGR power domain ack, firmware-load
  registers) that RTBuddy proceeds to write CPU_CONTROL RUN. Success test:
  "[rtkit:dcp] CPU_CONTROL RUN" appears, then the guest replies HELLO_REPLY to
  our HELLO. Until this fires, nothing above matters.

Stage B. RTKit + AFK transport. Once the guest replies to HELLO: drive EPMAP /
  STARTEP, then the AFK ring bring-up (INIT -> GETBUF -> INIT_TX/RX -> START) on
  the IOMFB/EPIC endpoints. Our apple_dcp.c already implements this handshake;
  verify it against real guest traffic and fix the ring header decode (rptr @0x40
  / wptr @0x80 / data @0xC0, magic "IOP ").

Stage C. IOMFB shmem RPC. Accept SET_SHMEM, answer the boot RPC chain
  (start_signal -> D120 boot_1 -> set_create_dfb -> create_default_fb ->
  setup_video_limits -> late_init_signal -> set_power_state), matching the iOS 27
  opcode numbers (capture and confirm; they differ from 13.x). Emit the D-callbacks
  the driver waits on.

Stage D. Swap capture. Accept swap_start / swap_submit, decode dcp_swap +
  dcp_surface for the iOS 27 layout (confirm offsets from captured packets),
  translate surf_iova[] through a real DART model to guest physical, read the
  surface.

Stage E. Present. Decompress the surface if compressed, convert the DCP fourcc
  to x8r8g8b8, and blit into the DarwinFB scanout region (or re-point the
  GraphicConsole surface at it) so real SpringBoard pixels reach the host window
  or VNC. This is the goal 3 criterion.

## Honest scope

This is the reverse engineering Asahi spent years on for macOS, applied to an
undocumented iOS 27 firmware tier with no public reference for its exact struct
layouts or opcode numbers. It is a large, multi-stage effort. Stage A alone
(coprocessor boot) is the gate and is non-trivial. The linear-framebuffer
shortcut is proven dead. Everything needed to proceed is captured above and in
the cached Asahi source; the method is the same one that solved goals 1 and 2:
capture real guest traffic, decode against this reference, implement, test one
hypothesis per boot.

## Stage A progress (this session)

Advanced Stage A one concrete brick, beyond the prior FINDINGS restore-ramdisk
state (where DARWIN_DCPFW + DCP_REGION "changed nothing" because RTBuddy never
instantiated). On the full-OS boot RTBuddy(DCP) does instantiate, so wiring the
firmware now engages the guest DCP code path.

Found the required runtime knobs (they were never passed in the goals 1/2 boots):
- DARWIN_DCPFW=firmware/dcpfw loads the 16.7 MB DCP firmware into a carved region
  and, in xnuboot_sptm.c, writes both region-base and region-size into the DT node
  arm-io/dcp/iop-dcp-nub (the success branch fires: "dcp firmware: 16695296 bytes
  at 0x104F947C000, region 0x6000000"). This is what iBoot does.
- DARWIN_PMGR maps the PMGR power/clock domains (30 regions) with auto-ack of
  power-state target->actual. The DCP firmware file (firmware/dcpfw) and the raw
  IPSW firmware (dcp-fw/t8140dcp.im4p, t8140dcp_restore.im4p) are already present.
- DARWIN_RTKIT (already used) maps the ASC mailbox at reg[0] 0x412E00000+0x88000
  and attaches apple_dcp.c. DARWIN_RTKIT / DARWIN_ASC / DARWIN_RTKIT_ANS are
  mutually exclusive (else-if in darwin.c). We keep DARWIN_RTKIT for the DCP.

New blocker pinned (next brick): with DARWIN_DCPFW enabled the guest panics early,
during IOKit matching, right after "AppleOLYHAL::start ... found wlan-olyhal-abort
boot-arg, bailing":
    panic: Kernel data abort at pc 0xfffffff02b03078c, far 0x8
    (kernelcache slide 0x20000000; static pc 0xb03078c; Darwin 27.0.0
     xnu-13432.2.10 RELEASE_ARM64_T8140).
The faulting code is a loop that re-reads a global array pointer each iteration:
    w19 = *(u32*)0xb63e05b8            ; element count, = 1 with dcpfw
    x8  = *(u64*)0xb6b26f0             ; array base pointer, element stride 72
    x10 = x8 + idx*72 ; ldr x1,[x10+8] ; FAULT when x8 == 0
    call 0xab1f6b0(x10+0x44, x1)
Under lldb (paused -S boot) at the loop entry the array pointer is a VALID heap
address (0xffffffea...) and count is 1; under the free-running boot the same site
faults with x8 = 0. So the function is called multiple times during boot to
iterate this one-element list, and one call catches the array pointer transiently
null while the count already reads 1 -- an init-order / concurrency window that
the dcpfw-region registration (count 0 -> 1) exposes under the free-run timing.
This does not happen without DARWIN_DCPFW (goals 1/2 boots, count 0, loop skipped).

Next steps for this brick: identify the list (the function enclosing 0xb030700,
the per-element callee 0xab1f6b0, and what the dcpfw region registers into it),
then either order the registration so the array store precedes the count
increment as the iterator sees it, or provide the missing backing so the entry is
consistent. Only after this passes can RTBuddy proceed toward CPU_CONTROL RUN and
the mailbox HELLO (the rest of Stage A). Reproduce:
  DARWIN_NOPAC=1 DARWIN_AIC=1 DARWIN_DART=1 DARWIN_DISP=all DARWIN_RTKIT=1 \
  DARWIN_FB=1 DARWIN_DCPFW=firmware/dcpfw DCP_NO_SCANOUT=1 qemu-... \
  -bootkc firmware/bootkc.md0.rwlivefs -ramdisk firmware/rootfs_norole.dmg ...

## Stage A progress, iteration 2 (this session)

Built a real fix for the dcpfw panic and ran the decisive experiments. Net result:
the DCP firmware / PMGR / the panic were NOT what blocks RTBuddy from booting the
coprocessor. The blocker is deeper and sits in the IOMFB init chain.

Fix built (null-guard, in the copy bootkc.md0.dcp): the DARWIN_DCPFW panic was a
kernel data abort at static pc 0xb03078c inside a memorystatus-adjacent function
(0xb030680) iterating a one-element global list (count at 0xb63e05b8, array pointer
at 0xb6b26f0, stride 72). Under lldb the array pointer is valid; under the free run
it reads null while count is already 1 (a non-atomic array-grow window the dcpfw
region registration exposes). Since we boot with DARWIN_NOPAC=1, the loop's PAC
sequence (eor/tst/b.eq/movk at 0xb03077c..0xb030788) is inert, so it was replaced
in place with a null guard: "cbz x8, 0xb0307a4" + 3 nops, i.e. if the array pointer
is null, skip the loop and return cleanly instead of dereferencing null. With this
patch the DARWIN_DCPFW boot no longer panics and reaches fixup / launchd normally.
The patch is inert without DARWIN_DCPFW (count 0, loop skipped), so goals 1/2 are
unaffected; bootkc.md0.rwlivefs is untouched.

Decisive experiments (each one full boot, DCP_NO_SCANOUT=1 to silence the painter):
- no firmware, no PMGR:            RTBuddy(DCP) start() runs, then zero mailbox MMIO.
- no firmware, DARWIN_PMGR=1:      same, zero mailbox MMIO, zero PMGR writes.
- DARWIN_DCPFW + PMGR (unpatched): kernel data abort 0xb03078c before launchd.
- DARWIN_DCPFW + PMGR + null-guard: boots fine, but RTBuddy(DCP) STILL does zero
  mailbox MMIO through guest 5 min. Only log line is "RTBuddy(DCP): start()".

Conclusion: RTBuddy(DCP)::start() attaches but never proceeds to power on / boot the
coprocessor (no CPU_CONTROL write, no HELLO handshake), regardless of firmware or
power. The coprocessor boot is deferred and its trigger never fires. The most likely
trigger is IOMFB completing init and requesting the DCP power on, and IOMFB does not
complete: the userspace IOMFB_FDR_Loader (loads the panel Factory Data Record /
calibration IOMFB needs) runs ~126 s and exits(1) every boot. So the next brick is
the IOMFB init chain, not RTBuddy itself:
  IOMFB_FDR_Loader exit(1)  ->  IOMFB never finishes init  ->  never asks the DCP to
  power on  ->  RTBuddy never boots the coprocessor  ->  no mailbox, no frames.

Next steps for this brick:
1. Find why IOMFB_FDR_Loader exits(1): what FDR source it reads (effaceable storage /
   nvram / a calibration file or partition) and whether that backing exists in the VM.
   Provide or stub the FDR so the loader succeeds, OR make IOMFB not require it.
2. If IOMFB still will not request the DCP after that, drive the coprocessor boot from
   the emulator side (self-announce is already available via DARWIN_RTKIT_ANNOUNCE but
   the guest did not respond, because RTBuddy has not set up the mailbox RX/IRQ yet;
   that only happens once RTBuddy actually boots the coprocessor). So (1) is the gate.
Only after the mailbox handshake starts do Stages B..E (AFK, IOMFB RPC, swap, present)
become reachable. This remains a large, multi-brick effort with unknown iOS-27 protocol
layouts past the handshake.

## Stage A progress, iteration 3 (this session): the boot is power-state deferred

Traced RTBuddyV2::start itself. The "RTBuddy(%s): start(%p)" format string
(0x7b21d69) is loaded at 0xa7bb7d0, inside RTBuddyV2::start at 0xa7bb728. Under lldb,
break at 0xfffffff02a7bb728, read the provider (x0) at entry and finish to read the
return value:
  HIT 1 provider 0xffffffe5bd906000 -> start() returns 1 (true)
  HIT 2 provider 0xffffffe5bd900000 -> start() returns 1 (true)
Both RTBuddies (ANS2 and DCP) start() SUCCEED. No REQUIRE-failed line appears in the
serial. So start() does not fail; it attaches and DEFERS the coprocessor boot.

This is the key correction: RTBuddy is not stuck or failing in start(). The ASC
coprocessor boot (map ASC regs, power on, load firmware into SRAM, write CPU_CONTROL
RUN, wait for HELLO) is driven from the IOKit power-state transition
(setPowerState to on), not from start(). That power-on is never requested, so the
boot function is never called and the guest never writes the ASC mailbox (consistent
with our apple_rtkit trace showing zero mailbox MMIO through 5 minutes).

On iOS the DCP power-on is requested by the display stack / IOMobileFramebuffer when
it brings up the panel. IOMFB does not complete: the userspace IOMFB_FDR_Loader
(/usr/bin/IOMFB_FDR_Loader, loads the panel Factory Data Record) runs ~126 s and
exits(1) every boot. So the confirmed gate is the IOMFB init / FDR chain, upstream of
the DCP power-on:
  IOMFB_FDR_Loader exit(1) -> IOMFB never finishes init -> nothing requests DCP power
  -> RTBuddy's deferred coprocessor boot never fires -> no mailbox handshake.

Concrete next brick (the FDR chain): find why IOMFB_FDR_Loader exits(1). It is a
userspace binary in the rootfs; its FDR source is effaceable storage / a calibration
record that the VM does not provide. Options: provide or stub the FDR backing so the
loader succeeds; or make IOMFB not require FDR; or, bypassing IOMFB, drive the DCP
power-on directly (force RTBuddy's setPowerState-to-on path, e.g. a bootkc patch that
calls the coprocessor-boot function from start, once that function is identified by
finding the ASC CPU_CONTROL (reg+0x44, RUN bit) write in the RTBuddy code). Any of
these only reaches the START of the mailbox handshake; Stages B..E (AFK, IOMFB RPC,
swap, present) with unknown iOS-27 layouts remain beyond it.

## Stage A/B iteration 4 (this session): the full gate chain, down to VM-mode PM

Pursued both the FDR path (A) and the direct-power-on path (B); they converge on one
root. Mounted the rootfs read-only and reverse-engineered /usr/bin/IOMFB_FDR_Loader
(arm64e, 328 KB, launched by an IOKit matching event on IOMFB publishing the
IOMFBLaunchFDR property):
- It needs a live display instance: strings "Failed to get panel_id", "Failed to get
  als_id", "Failed to create acss_id", "Failed to get DIC id", "Loading embedded
  instance %d", "All done display instance %d". panel_id/als_id/DIC come from the
  booted DCP/panel. No booted DCP -> no panel_id -> the loader cannot proceed.
- Its real FDR source is effaceable NAND via AppleNVMeEAN: "IOServiceOpen on
  AppleNVMeEAN failed", "Get EANSize failed", "Read EAN failed", "ean_open". We boot
  from a RAM ramdisk with no NVMe/ANS storage, so EAN open fails.
- It has fallbacks ("No matching FDR data, using default", "using default"), so EAN is
  not necessarily fatal; the fatal path is the missing display instance (no panel_id).
So A (the FDR loader) is DOWNSTREAM of B (the DCP boot), not upstream: it needs the
DCP already booted to read panel data. Fixing FDR does not boot the DCP.

B (the DCP coprocessor boot) is therefore the true gate, and it traces down to
platform power management. New evidence:
- Both RTBuddies (DCP and ANS2) start() succeed and both defer their coprocessor boot;
  neither ever drives its ASC mailbox. It is not DCP-specific.
- With DARWIN_PMGR=1 the guest makes ZERO reads and ZERO writes to our emulated PMGR
  registers, yet the OS boots fine. So the guest is not using our PMGR to gate power.
- The serial shows "AMFI: Booted in a VM" and, crucially,
  "AMFI: skipping PMGRAON latch due to AVP". The guest detects the Apple Virtual
  Platform (AVP) and SKIPS PMGR power operations. In VM mode the coprocessor power /
  bring-up path is different from real hardware: it is expected to be provided by the
  virtual platform (as Apple's own Virtualization.framework does for the paravirtual
  vphone), not driven through emulated PMGR the way real iBoot/XNU would.

Conclusion / the complete goal-3 gate chain, from pixels down:
  guest pixels
   <- DCP produces frames (IOMFB swap_submit -> DART -> compressed surface -> present)
   <- IOMFB completes init (needs FDR/panel data, needs a booted DCP)
   <- DCP coprocessor is booted (ASC mailbox HELLO handshake)
   <- RTBuddy runs its deferred coprocessor-boot (setPowerState to on)
   <- the platform powers on the DCP power domain
   <- BUT in VM mode ("AVP") the guest skips PMGR and expects the virtual platform to
      handle coprocessor power/bring-up, which this emulation does not model.
So the deepest brick is VM-mode platform bring-up of the DCP coprocessor: model what
the guest's AVP path expects (the coprocessor presented already powered/booted, or the
specific VM power handshake), so RTBuddy proceeds to set up and drive the ASC mailbox.
Only then do the AFK/EPIC/IOMFB/swap/DART/decompress stages (with unknown iOS-27
layouts) become reachable. This is Asahi-scale reverse engineering for an A14+ DCP that
no public project has done; it is a multi-session frontier, now fully mapped here.

## Stage A/B iteration 5 (this session): hv_vmm_present is AMFI-only; the real key is iBoot pre-boot

Corrected a wrong lead and found the actionable root. The "Booted in a VM" / "skipping
PMGRAON latch due to AVP" behaviour is driven by the kern.hv_vmm_present sysctl, but its
only effect here is AMFI-internal: the AMFI code at 0x91a6404 reads hv_vmm_present via a
sysctl lookup (call at 0x91a6424) and, if set, stores 1 to an AMFI "is-VM" byte at
0x8091681 and logs "Booted in a VM". That gates only AMFI's PMGRAON security latch, not
the DCP power path. So hv_vmm_present is a red herring for the DCP boot; forcing it to 0
would only change AMFI and would push the guest to drive real hardware we do not fully
model (riskier, not helpful).

The actionable root is the display power chicken-and-egg and how real platforms resolve
it:
- IOMFB_FDR_Loader needs panel_id/als_id/DIC from a live display instance (a booted DCP).
- The DCP is powered on by its display client (IOMFB) requesting power.
- So DCP-power needs IOMFB, and IOMFB (panel_id) needs a powered DCP: a cycle.
On real hardware, and under Apple's own Virtualization.framework, this cycle does not
exist because iBoot boots the DCP coprocessor BEFORE XNU: it powers the ASC, loads the
DCP firmware into SRAM, and starts it, so when XNU's RTBuddy attaches, the coprocessor is
ALREADY RUNNING and answers immediately (panel data available at once). qemu-sptm stands
in for iBoot but does NOT pre-boot the DCP coprocessor; our apple_rtkit only sends the
RTKit HELLO after the guest writes CPU_CONTROL RUN, and RTBuddy never gets to that because
its boot is deferred and the cycle above never resolves.

Concrete engineering direction (next session): make qemu-sptm present the DCP as an
already-running coprocessor, the way iBoot leaves it:
1. In apple_rtkit / apple_dcp, model the ASC as "booted": drive the RTKit HELLO -> EPMAP
   -> (await STARTEP) handshake proactively at attach, and set whatever ASC status /
   mailbox "IOP running" indicator RTBuddy reads to decide the coprocessor is already up,
   so RTBuddy attaches instead of cold-booting and sets up its mailbox RX/IRQ.
2. Determine exactly what RTBuddyV2 checks to distinguish "cold boot the IOP" from
   "attach to a running IOP" (a status register, a DT property such as the iop-dcp-nub
   "pre-loaded"/"running" flag, or a HELLO it expects unprompted). The earlier
   DARWIN_RTKIT_ANNOUNCE (proactive HELLO) got no response precisely because RTBuddy had
   not set up the mailbox RX yet; that setup is what must be triggered.
3. Only then does the mailbox handshake begin, unblocking Stages B..E (AFK, IOMFB RPC,
   swap, DART, present) with the still-unknown iOS-27 protocol layouts.

Net: goal 3 is a fully mapped, multi-session frontier. This session advanced Stage A from
"restore-ramdisk, kexts never load" to a precise, root-caused model: full-OS boot loads
the display stack, RTBuddy attaches successfully, and the one remaining kernel-side gate
is that the DCP coprocessor is never brought up because qemu-sptm does not pre-boot it as
iBoot would. That is the concrete thing to build next.

## Stage A/B iteration 6 (this session): the DCP boot is governed by IOKit power-plane properties

Ruled out the remaining shortcuts and pinned the exact machinery. Re-tested a proactive
RTKit HELLO with the full config (bootkc.md0.dcp + firmware + PMGR + null-guard,
DARWIN_RTKIT_ANNOUNCE): HELLO is sent but the guest never replies, and the ASC mailbox is
never touched in 12+ minutes, so RTBuddy's mailbox bring-up genuinely never runs (not just
late). RTBuddyV2::start is a very large function (its ret is more than 0x800 bytes past the
entry) and returns success; the coprocessor bring-up is not inline-and-skipped but sits in
the power-managed path.

The iop-dcp-nub / dcp DT node carries the power-management properties that govern this:
  join-power-plane, remote-power-state, require-force-wakeup, cold-boot-after-hibernate,
  no-firmware-service, region-base, region-size, dcp-controls-reg-index,
  dcp-controls-value-on/off, first-frame-response-threshold.
So the DCP is a join-power-plane device whose bring-up requires a force-wakeup /
power-state transition (require-force-wakeup, remote-power-state). Nothing issues that
transition in this headless ramdisk boot, so RTBuddyV2::setPowerState-to-on never runs.

State of the levers tried this session (all dead-ended or deferred, documented above):
  firmware load + DT wiring (DARWIN_DCPFW): works, but only fixes the carve panic.
  PMGR (DARWIN_PMGR): guest never touches it; boot fine without it.
  proactive HELLO (DARWIN_RTKIT_ANNOUNCE): no guest response, mailbox RX not set up.
  hv_vmm_present / AVP: AMFI-only, red herring for the DCP.
  locate the ASC CPU_CONTROL-RUN write to patch a direct boot: not a str [x,#0x44];
    it goes through a register abstraction, not statically locatable by that pattern.

What cracking this brick actually requires (dedicated deep RE, next effort):
1. Find RTBuddyV2::setPowerState via the class vtable (read [this] on a live DCP instance,
   index the IOService setPowerState slot for this XNU build) and confirm it is never
   called on the DCP; then find what should call it (the power-plane parent / client).
2. Either drive that power-state transition (model the join-power-plane / force-wakeup the
   DCP expects, or provide the display-client power request), or patch RTBuddyV2 to run its
   coprocessor bring-up unconditionally in start (requires locating the bring-up method
   behind the register abstraction and its preconditions).
3. Once the mailbox handshake starts, Stages B..E (AFK, IOMFB RPC, swap, DART, present) with
   unknown iOS-27 layouts remain.

Honest status: goal 3 is a fully mapped, Asahi-scale, multi-session frontier. This session
took Stage A from the restore-ramdisk dead end to a precise, root-caused model of a full-OS
boot where the entire display stack attaches and the single kernel-side gate is the DCP
coprocessor's power-plane bring-up never being triggered. That is the concrete thing a
dedicated next effort must build.

## MAJOR PIVOT (this session): iOS in a VM uses paravirtual graphics, not the DCP

Investigating new ground settled the direction: emulating the real DCP is the wrong
path for a VM. In a VM, iOS does not bring up the physical Display CoProcessor at all
(this is exactly why RTBuddy(DCP) never powers on and why AMFI skips the PMGRAON latch
"due to AVP"). Apple's own Apple-silicon VMs present a PARAVIRTUAL GPU instead, and all
the pieces to do the same already exist here:

- iOS 27 kernelcache HAS the paravirtual GPU driver: the class "AppleParavirtGPU" is
  registered in bootkc, next to "AppleVirtIONeuralEngineDevice" and
  "AppleVirtIOAgentDevice" (a whole VM-mode paravirtual/virtio driver family), plus the
  userspace side "com.apple.gpusw.ParavirtualizedGraphicsGPUTask". So the guest ships the
  driver; nothing to install.
- qemu-sptm ALREADY compiles the matching host device: hw/display/apple-gfx.m +
  apple-gfx-mmio.m (the AArch64 MMIO variant), and the build reports
  "ParavirtualizedGraphics support: YES"; apple_gfx_mmio_* symbols are in the binary.
  apple-gfx is a thin shim over Apple's host ParavirtualizedGraphics.framework (PVG):
  it maps guest RAM, renders the guest's Metal-style command stream through host Metal,
  and pushes surface/cursor updates back. It exposes two MMIO regions (a GFX region sized
  by PGDeviceDescriptor.mmioLength and a fixed 0x10000 IOSFC region) and two IRQs.
- The host HAS the framework: /System/Library/Frameworks/ParavirtualizedGraphics.framework
  is present on this Intel Mac (Metal works on Intel too).
- The wiring template exists: hw/vmapple/vmapple.c create_gfx() does
  qdev_new("apple-gfx-mmio"); sysbus_mmio_map(gfx,0,GFX_base); sysbus_mmio_map(gfx,1,
  IOSFC_base); sysbus_connect_irq(gfx,0/1, ...). vmapple uses GIC; our darwin machine uses
  AIC, so the IRQ wiring adapts to aic_irq_line().

Why this beats the DCP: it is the path Apple's VMs actually use; it avoids the DCP power
chicken-and-egg, the FDR/panel_id dependency, compressed surfaces, and the unknown iOS-27
IOMFB protocol. It reuses working QEMU code and the host framework.

Open questions to resolve before/while wiring (all flagged honestly):
1. The exact DT match for AppleParavirtGPU: its IOKit personality is NOT a literal string
   in __PRELINK_INFO (0x4358000+0x280000) and no "apple,*gpu/paravirt/gfx" compatible was
   found, so the node name/compatible the guest matches is undocumented and buried. Must
   be recovered by RE'ing the AppleParavirtGPU IOService (its probe/match, superclass in
   IOGPUFamily) or from a reference Apple iOS-VM device tree. The existing DT has a real
   "gpu,t8140" node for AGX; the VM path likely replaces/augments it with a paravirt match.
2. Whether iOS's AppleParavirtGPU speaks a PVG protocol the host framework's shim accepts
   (macOS guests are confirmed; iOS is unverified - Apple's iOS-in-VM notes even say the
   GPU is not emulated and a plain virtual framebuffer is used for that limited scenario).
3. Whether PVG works host-side on Intel with an iOS guest.
4. The Apple ADT parser used here cannot create/resize nodes at runtime (only edit
   existing property values), so adding the paravirt-gpu DT node needs an offline
   dt_fixup pass, not a runtime patch.

Concrete build plan (paravirtual path):
A. Recover AppleParavirtGPU's DT match (RE the kext's probe/superclass, or diff against a
   real Apple VM iOS device tree).
B. Add that node to dtree_ios offline (dt_fixup), pointing at the MMIO base we choose.
C. Wire apple-gfx-mmio into hw/arm/darwin.c behind a DARWIN_PVGFX env: create the device,
   map its two MMIO regions, connect its two IRQs via aic_irq_line, realize it. Rebuild.
D. Boot; watch the guest IOKit matching for AppleParavirtGPU attaching to our device;
   iterate the compatible/registers until it binds and PVG starts producing frames into a
   surface we scan out to the DarwinFB/host window.

This supersedes the DCP-coprocessor line for goal 3. The DCP analysis (Stages A/B iters
1..6) remains valid as the proof that the physical path is a dead end in a VM, which is
what pointed here.

## Paravirtual path, reconnaissance complete: AppleParavirtGPU lives in the aux kernelcache

Followed the paravirtual pivot down. AppleParavirtGPU has NO IOKit personality in the boot
kernelcache __PRELINK_INFO (which is a plain XML _PrelinkInfoDictionary): searching it for
ParavirtGPU / Paravirt / VirtIO / virtio / ParavirtualizedGraphics / AppleVirtualPlatform
returns zero personalities (only an unrelated IODPTXVirtualPort). The class name appears once
in a class-registration table, so the code is referenced but the matching driver + its
personality are not in the boot KC. iOS splits its kernelcache: the paravirtual / VM-mode
drivers (AppleParavirtGPU, AppleVirtIOAgentDevice, AppleVirtIONeuralEngineDevice) live in the
AUXILIARY kernelcache loaded later from /System/Library/KernelCollections in the rootfs, and
they are enumerated by an undocumented VM-platform mechanism (no AppleVirtualPlatform/virtio
personality is public or in the boot KC).

Net reconnaissance for goal 3 (both paths mapped):
- DCP path: dead end in a VM. RTBuddy(DCP) attaches but its coprocessor boot is power-plane
  deferred and never triggered; AMFI skips the PMGRAON latch "due to AVP". iOS does not power
  the physical DCP in a VM by design. (Stages A/B iters 1..6.)
- Paravirtual path: the correct direction and Apple's actual VM design, and the host pieces
  exist (apple-gfx-mmio compiled, ParavirtualizedGraphics.framework present). But it is also a
  deep, undocumented build: (1) AppleParavirtGPU's match/personality is in the aux kernelcache,
  not the boot KC, and must be recovered from there; (2) it is enumerated by an undocumented
  VM-platform bus, not a simple DT node; (3) the Apple ADT parser here cannot add nodes at
  runtime; (4) a fundamental viability risk: apple-gfx is a shim over Apple's host PVG
  framework, macOS-guest-proven only, and it is unverified whether an iOS guest's
  AppleParavirtGPU is protocol-compatible and whether PVG runs host-side on an Intel Mac with
  an iOS guest (Apple never officially supported iOS VMs and its iOS-VM notes say the GPU is
  not emulated).

Honest bottom line: goal 3 (guest pixels) on iOS 27 / t8140 is a genuine, multi-unknown
research frontier by BOTH paths, with the paravirtual path being the right but still large and
risk-bearing direction. The next concrete build steps (recover AppleParavirtGPU's aux-KC match,
model the VM-platform enumeration, wire apple-gfx-mmio, verify PVG-on-Intel) are a dedicated,
multi-session engineering effort whose feasibility hinges on the unverified PVG-iOS-on-Intel
question. This document is the complete map for that effort. Goals 1 and 2 are done and
independent of this.

## DEFINITIVE (this session): the paravirtual path requires an Apple Silicon host; goal 3 pixels are not viable on Intel

Tested both the viability of PVG on this Intel host (A) and the presence of the guest
driver in this build (B). Both are negative, definitively.

A. PVG viability on Intel (direct test against the host framework, /tmp/pvg2.m):
   - dlopen /System/Library/Frameworks/ParavirtualizedGraphics.framework: OK (loads on Intel).
   - PGDeviceDescriptor class: found; instance works; mmioLength = 0x4000.
   - PGNewDeviceWithDescriptor symbol: found.
   - PGNewDeviceWithDescriptor(desc) with a FULL descriptor (createTask/destroyTask/mapMemory/
     unmapMemory/readMemory/raiseInterrupt no-op handlers, exactly the set apple-gfx wires):
     returns NULL.
   So Apple's ParavirtualizedGraphics.framework LOADS on Intel but REFUSES to create a device.
   PVG is Apple-silicon-only; apple-gfx (which is a thin shim over this framework) therefore
   cannot produce frames on an Intel host, regardless of guest wiring.

B. Guest driver presence in this build: the rootfs (a physical-device IPSW for iPhone17,3)
   has System/Library/{Extensions,DriverExtensions,ExtensionKit,Caches} but NO
   System/Library/KernelCollections, no auxiliary kernelcache, and no kernelcache file. So
   AppleParavirtGPU is not a loadable/matchable driver in this build (it is only a referenced
   class name in the boot KC with no IOKit personality). The paravirtual/VM driver family is
   not shipped in a physical-device image.

Definitive conclusion for goal 3 on an Intel Mac with iOS 27 / t8140:
   - simple/boot framebuffer: does not exist on t8140 (XNU renders nothing to boot_args.Video).
   - real DCP coprocessor: a VM dead end (iOS does not power it in a VM; RTBuddy boot never
     fires; AMFI skips PMGRAON due to AVP).
   - paravirtual PVG (the only VM-viable graphics path): requires an Apple Silicon HOST; Apple's
     PVG framework refuses device creation on Intel (verified).
   Therefore there is NO viable path to guest pixels for this OS/SoC on an Intel host with the
   available components. Reaching goal 3 would require one of: (a) an Apple Silicon host so the
   PVG framework works and apple-gfx can be wired up (plus a build/DT that actually loads and
   binds AppleParavirtGPU); (b) a full from-scratch reimplementation of Apple's proprietary PVG
   MMIO/ring protocol inside QEMU (large, undocumented, and still needs a guest that loads
   AppleParavirtGPU); or (c) full DCP/RTBuddy coprocessor emulation (Asahi-scale, and the VM
   deliberately avoids that path). This is an empirically verified host/platform limitation,
   not an emulation-effort gap. Goals 1 and 2 are unaffected and complete.

## BUILD STARTED: the DCP-force foundation (this session)

Committed to building the real thing (force the DCP coprocessor boot + implement the iOS-27
IOMFB protocol), since the DCP is the only path where the guest driver is actually present in
this build (PVG is Apple-silicon-only on the host; the paravirtual driver is not loadable here).
Laid the concrete foundation for the force:

Force target mechanics (all recovered by RE this session, addresses are short static VA,
runtime = +0x20000000, file offset = -0x7004000):
- DCP display-driver init/probe: 0x89efb28 (runs; reads join-power-plane, require-force-wakeup
  into [this+0x2cc], dcp-controls-value-on into [this+0x2d4]; this in x19; retab at 0x89f1a34).
- DCP power-transition (writes dcp-controls-value-on to the control reg and boots): 0x89f3c4c,
  called from the power handler 0x89f3b58 at 0x89f3bcc/0x89f3bec.
- DCP boot/wake helper: 0x89f2620, invoked as f(x0=this, w1=1, x2=this) on the power-on path
  (see 0x89f3df0..0x89f3e18).
- Generic IOKit force: IOService::temporaryPowerClampOn (symbol
  __ZN9IOService21temporaryPowerClampOnE present) clamps a device to max power;
  changePowerStateToPriv/makeUsable/activityTickle symbols also present.
- RTBuddyV2::start = 0xa7bb728 (coprocessor runtime; succeeds, defers the ASC mailbox bring-up).

The obstacle to a one-instruction patch: IOKit PM methods are dispatched via the vtable with
PAC (blraa), so their static addresses are not reachable from a direct bl for a simple call
injection, and the target functions (RTBuddyV2::start, the DCP init) are large with far returns
and no free instruction slots where `this` is guaranteed live. So the clean force is a
code-cave / trampoline patch (the same technique the rwroot mountroot-RW stub used): place a
small stub that loads `this` and calls the DCP boot 0x89f2620 (or temporaryPowerClampOn), and
redirect one existing call site at the tail of the DCP init (0x89efb28, before the 0x89f1a34
retab) to the stub, then fall through. That is the next concrete brick.

Full build roadmap from here (each a real, multi-brick stage):
1. Force the DCP coprocessor boot via the code-cave stub above so RTBuddy sets up the ASC
   mailbox; verify by seeing the guest write CPU_CONTROL / our apple_rtkit logging the HELLO
   handshake. (start here)
2. Complete the RTKit management + AFK ring handshake (apple_rtkit.c + apple_dcp.c already do
   most of it; verify against real guest traffic once the mailbox is live).
3. Implement the IOMFB shmem-RPC responder for the iOS-27 protocol tier in apple_dcp.c: capture
   the guest's real IOMFB messages (our RECV handler already hex-dumps the TX ring), decode the
   swap_start/swap_submit and the surface descriptors against the Asahi reference in this doc,
   adjusting for the iOS-27 opcode/struct differences (the large, Asahi-scale part).
4. DART-translate the surface DVA to guest physical, read + (if needed) decompress the surface,
   convert the DCP fourcc to x8r8g8b8, and blit it into the DarwinFB scanout so real guest
   frames reach the host window / VNC. That is the goal-3 criterion.

Honest scope: stage 1 (force) is the immediate concrete brick and is buildable via the
code-cave. Stage 3 (the iOS-27 IOMFB protocol) is the Asahi-scale, multi-session part. This is
the real build; it advances brick by brick, not in one turn.

---

## MILESTONE: full iOS UI stack boots; goals 1 and 2 confirmed live; goal 3 gate corrected

Verified in a single full-OS boot (rootfs_with_cryptex.dmg + bootkc.md0.disp
[writable-root fix + secureproxy_v2] + dtree_ios, env DARWIN_AIC=1 DARWIN_DART=1
DARWIN_DISP=all DARWIN_RTKIT=1 DARWIN_FB=1 DARWIN_DCPFW, memory 20G):

- The dyld shared cache now MAPS ("dyld cache mapped system-wide: customer"). The prior
  "(null) not loaded" wall is gone; the earlier dyld-cache symlink fix cleared it. The
  residual "auth GOTs: unmapped" plus check_np errno 12 is a non-fatal warning and
  launchd continues.
- GOAL 1 (writable /private/var) confirmed live: launchd runs the "fixup-mobile-tmp"
  boot task Doing then Finished, then "Early boot complete. Continuing system boot." No
  EROFS.
- GOAL 2 (SpringBoard up, no three-strike reboot) confirmed live: the full UI stack
  spawns (com.apple.SpringBoard "launching: system support", backboardd as pid 44,
  IOMFB_FDR_Loader), and the boot stays alive to guest time 00:09:00 (9 minutes) with
  zero SpringBoard exit events and zero reset markers. Every apparent panic string is a
  false positive (spawn-panic-crash-behavior plist keys, the watchdogd process name,
  non-enforcing AMFI launch-constraint violations).

Goal 3 gate, now observed in the correct context (full boot, real IOMFB client):
RTBuddy(DCP)::start() still parks at waitForMatchingService for the secure-world
SecureRTBuddyDCP service, which never publishes here. So RTBuddy(DCP) never registers
its service, IOMFB and AppleCLCD never attach, the coprocessor is never taken out of
reset (no CPU_CONTROL RUN, no mailbox traffic), and there is nothing to scan out. This
is upstream of the QEMU IOMFB work in the staged plan above: the mailbox cannot go live
until RTBuddy(DCP)::start() completes.

Settled dead ends (do not revisit):
- XNU linear boot framebuffer is dead on iOS 27. boot_args.Video is wired correctly
  (v_baseAddr, the /vram device-tree reg, display-scale) yet a dump of the guest
  framebuffer region through full userland is all zeros. iOS 27 draws nothing to a CPU
  framebuffer; display is entirely DCP. The boot-log painter is not a substitute.
- The old route_timeout / route / route_skip kernel experiments are superseded by
  secureproxy_v2 and must not be stacked on it: doing so panics early in
  AppleARMLightEmUp::start (kernel data abort, faulting address 0x8) before RTBuddy(DCP)
  even starts, by perturbing driver-match ordering.

Corrected next step for goal 3: make RTBuddy(DCP)::start() complete WITHOUT perturbing
driver matching, by publishing a stub SecureRTBuddyDCP IOService so
waitForMatchingService resolves for real (rather than forcing the wait to return null
and then chasing downstream null-guards). Only then does the mailbox go live and the
staged IOMFB scanout work begin.

---

## PROGRESS: AppleARMLightEmUp panic fixed; SecureRTBuddyProxy publish applied; gate still closed

Built firmware/bootkc.md0.pub = bootkc.md0.disp (writable-root + secureproxy_v2) plus:

1. SecureRTBuddyProxy publish patch (from static analysis of SecureRTBuddyProxy::start at
   file offset 0x3823df4): NOP the exclaves-down short-circuit (b.eq at file offset
   0x3824014) and retarget the missing-exclave-endpoint branch (cbz at 0x3824114) to the
   finalize/publish block 0xa8282d0, so the proxy nub reaches registerService even without
   a live secure world. The finalize block does not dereference the null tightbeam fields.
2. Null-array guard for the AppleARMLightEmUp::start panic. Both the earlier route patches
   and this publish patch tripped a kernel data abort at pc 0xb03078c (fault address 0x8):
   a dispatch loop whose count global is >= 1 while its array pointer global is null. The
   instructions before the load are signed-pointer canonicalization (not inert under the
   no-PAC boot: the movk really executes and poisons the pointer). Correct fix, verified by
   disassembly: change the b.eq at 0xb030784 to cbz x8, loop-end (skip the loop when the
   array pointer is null) and replace the movk at 0xb030788 with nop so a valid pointer
   reaches the load uncorrupted.

Result booting bootkc.md0.pub with the full rootfs: no panic, goal 1 still live
(fixup-mobile-tmp), RTBuddy(DCP) starts, backboardd reaches running, boot healthy to ten
minutes. But the DCP gate stays closed: no CPU_CONTROL RUN, no mailbox traffic, and no
IOMobileFramebuffer or RTBuddyService attach in the serial. Publishing the proxy did not by
itself make RTBuddy(DCP)::start complete and boot the coprocessor.

Diagnosis: RTBuddy takes the coprocessor out of reset (writes CPU_CONTROL RUN) only after
the route reports powered, through the rtbuddyservice power-state handshake. A bare publish
or a null/skipped secure route never reports powered, so the RUN write never happens.
Corroborating, RTBuddy(ANS2) has no secure route and works, yet the QEMU ANS mailbox also
sees no traffic, because ANS storage is satisfied through a faked NVMe BOOT_STATUS rather
than a live RTKit handshake. So the mailbox RUN write we watch for is produced only once
RTBuddy genuinely powers the coprocessor on.

Next brick: locate RTBuddy(DCP)'s "route powered, take coprocessor out of reset, write
CPU_CONTROL RUN" decision and either satisfy the power-state op with a powered return or
bypass the power gate to drive the coprocessor boot directly. bootkc.md0.pub is the clean,
panic-free base to patch on, with goals 1 and 2 intact.

---

## PROGRESS: route-loop fixed with a CBZ retarget; mailbox still silent (power-on not reached)

Runtime debugging (lldb over the gdbstub) settled two things on the publish build:
- SecureRTBuddyProxy::start is never called (its driver does not match in this VM), so the
  publish patch was dead code.
- RTBuddy(DCP) blocks inside waitForMatchingService and never returns.

So the wait must be made non-blocking. Disassembly of the route loop shows the branch that
fires on a null resolved route leads to a fatal assert, while the loop's own success path
continues to the next route. The clean fix is a single-instruction retarget of that branch so a
missing secure route is treated as handled and the loop continues, combined with the poll-once
wait timeout, the AppleARMLightEmUp null-array guard, and the existing secure-route null guard.

Result: no panic, the route loop completes, RTBuddy(DCP) starts, backboardd runs, and the boot
stays healthy for nine minutes with goals 1 and 2 intact. But the DCP mailbox is still silent:
no CPU_CONTROL write, no HELLO. Completing the route loop does not by itself drive the
coprocessor power-on.

Corroborating, the storage coprocessor (which works through a faked NVMe boot status) also
produces no mailbox traffic, so the low-level power-on write is apparently not exercised for any
coprocessor in this VM. Leading hypothesis: the kernel treats the coprocessor as already running
and the power-on method early-returns without writing CPU_CONTROL. Next step is to breakpoint
the power-on method and the register writer at runtime to see which guard skips the write, and in
parallel to consider having the emulated coprocessor announce itself once the driver attaches,
rather than waiting to be taken out of reset. The route-fixed kernelcache is the clean base for
that work.

---

## DEFINITIVE: bypassing the route is not enough; RTBuddy drives no coprocessor bring-up

Reliable evidence (a logging MMIO stub compiled into the machine, since kernel breakpoints do
not install over this gdbstub): across a full boot of the route-fixed kernelcache, the guest
makes exactly one DCP-related hardware write, a single value 0x10 to a dcp expert register, and
zero writes to the ASC CPU_CONTROL register at any window, and no mailbox activity at all.

So making the service wait non-blocking and letting the route loop complete is necessary but
not sufficient. RTBuddy brings the display coprocessor out of reset only after its route
reports powered, through the rtbuddyservice power-state protocol. With a null or bypassed route
there is no powered report, so RTBuddy never programs the mailbox and never starts the
handshake. The lone expert-register write is a power-domain poke from another driver, not the
coprocessor run signal.

Two remaining options for goal 3, both real work:

- Faithful: implement the exclaves and Tightbeam rtbuddyservice power-state responder so the
  real route reports powered. Largest path; needs the secure-world transport modeled.
- Pragmatic: kernel-patch RTBuddy's power-state decision so the route reads as powered and
  RTBuddy proceeds to program the mailbox, after which the existing mailbox and IOMFB model and
  a small model polarity or self-announce tweak take over. Smaller, but another RTBuddy patch
  cycle, and the stub route object needs its post-powered field reads guarded.

The route-fixed kernelcache (route loop clean, goals 1 and 2 intact, full UI up for nine
minutes) is the base for the pragmatic path.

---

## Power-on path is reachable and null-safe; blocker is the PM power-up issuance

Static call-graph analysis (reliable) established the reset-deassert chain: the CPU_CONTROL
writer is called only by the coprocessor power-on method, whose sole caller sits inside RTBuddy's
setPowerState state machine on the power-up command branch. That entire power-up branch was
traced to fall through to the power-on call even when the secure route is null, with no early
return. So if a power-up is ever issued to the display RTBuddy, the coprocessor comes out of
reset regardless of the null route.

Correction to the earlier idea: the route-ready checks are all gated behind a non-null secure
route, so with the route bypassed they are dead code and must not be patched.

The real blocker is that nothing issues the power-up command to the display RTBuddy. It is
IOKit power-management mediated, and RTBuddy requests power-up only after its route reports
powered, which is the chicken-and-egg with the null route. The exact power-management issuance
gate was not isolated from static analysis alone, and runtime observability is unavailable in
this environment: neither software nor hardware breakpoints over the emulator debug stub fire on
kernel addresses (the guest runs to the graphical stack with zero hits), so the debugger cannot
watch the power-management calls.

Remaining options for goal 3, all real work: implement the secure-world power-state responder so
the real route reports powered; or force the power-up issuance for the display RTBuddy after
isolating the gate (via compiled-in serial instrumentation patched into the RTBuddy
power-management entry points, since the debugger is unusable, or further static analysis); or a
code-cave that drives the power-up directly from the driver's start tail. The downstream path is
proven reachable and null-safe, and the existing mailbox and IOMFB model plus a small polarity
adjustment take over once the coprocessor is powered.

Goals 1 and 2 remain delivered and verified. Goal 3 is reduced to this single power-management
issuance gate on the route-fixed kernelcache base.

---

## BREAKTHROUGH: DCP mailbox brought live by our own injected kernel code

We stopped trying to trick Apple's power-management into powering the display coprocessor and
instead wrote our own kernel routine that does it directly. A code-cave hooked onto the
RTBuddy start routine's completion loads the coprocessor object from the driver, gates strictly
to the display coprocessor by its device-tree name (so the storage coprocessor is never
touched), skips if it is already running, and then calls the low-level run routine to take the
coprocessor out of reset. All patch bytes were assembled and verified by re-disassembly before
applying.

Result on boot: for the first time the display coprocessor mailbox shows activity. Our routine
writes the run bit to the coprocessor control register at the mailbox base, the emulator's
mailbox model detects the reset-deassert, sends the RTKit HELLO, and the coprocessor mailbox
interrupt is delivered to the guest and acknowledged. It fires exactly once, only for the
display coprocessor, with no panic and a healthy boot.

What remains is completing the handshake. The driver takes the interrupt but does not yet drain
the incoming mailbox to read our HELLO. The likely cause is timing: we force the power-up at the
end of the start routine, before the driver arms its mailbox receive path (which normally
happens later in the power-management flow we bypassed), so the HELLO arrives before the
receiver is listening. Next steps are to delay or repeat the HELLO so the driver has time to arm
its receive path, or to move the hook to a later once-per-coprocessor site that runs after the
receive path is set up. This is the first time the emulated coprocessor and the real driver have
exchanged anything, which is the milestone that unblocks the mailbox and, after it, the display
pipeline.

---

## Mailbox live confirmed; handshake blocked on the driver arming its receive path

Iterating the injected routine established, reliably, both the win and the remaining wall.

The win holds: calling the low-level run routine takes the coprocessor out of reset, our mailbox
model detects it and sends the RTKit HELLO, and the coprocessor interrupt is delivered to the
guest.

The wall: after HELLO the driver never reads the mailbox. It takes the interrupt and acknowledges
it repeatedly but its handler touches no mailbox register at all, which means the interrupt it
receives is not its mailbox receive handler. The driver arms its mailbox receive path (interrupt
handler plus endpoint processing) only through the normal power-management power-up run on its
command gate. Calling the power-on method directly from the driver start tail deadlocks, and even
ordering our HELLO first so the deadlock clears does not arm the receive path. So forcing the
hardware reset gives us a live coprocessor from the emulator side, but the driver software is
never put into the listening state.

Next step, now precisely bounded: trigger the driver's power-up asynchronously so the power-on
method runs on its own gate and arms the receive path, for example by calling the public
power-management request method rather than the internal power-on directly. Then the HELLO is
caught by the now-armed receiver and the handshake proceeds into endpoint discovery and the
display transport. Goals 1 and 2 remain intact throughout; the minimal mailbox-live result is
preserved as a reference build.

---

## Receive-path arming is entangled with the absent secure-route object

Driving the driver's power-up through its command gate no longer deadlocks, but it faults: the
power-up path loads the driver's route/transport object and calls into it, and that object is
null because the secure-world route was never established in this VM. The fault is a plain null
dereference of that object.

This sharpens the remaining work. The driver arms its mailbox receive path by calling into its
route object; with no secure world that object is absent, so the receive path cannot arm through
the normal flow even after the coprocessor is powered. The same secure-world dependency that
gated power now also gates receive. Guarding the null dereferences would only skip the arming,
not perform it, because that very object is what would arm the receiver.

So the concrete remaining brick is to provide our own small route/transport object for the driver
to call, whose methods drive the normal-world mailbox we already model, installed where the
driver expects its route. That is a self-contained piece of kernel code we write, and it lets the
power-up path arm the receiver against our mailbox and complete the handshake. It is bounded work
and is the real next step. The mailbox-live result and goals 1 and 2 remain intact.

---

## DECISIVE: SpringBoard pixels require a GPU that is not emulated; only kernel-drawn pixels are reachable

The bypass-the-coprocessor investigation settled the pixel question at the architecture level.

The mobile framebuffer is a remote-procedure shim to the display coprocessor: surfaces are handed
to the coprocessor as device-virtual addresses and are never exposed as a CPU-addressable scanout
base, so there is nothing to copy on that path. More fundamentally, the iOS 27 user-interface
compositor requires the GPU. There is no on-device software rasterizer for the interface, so with
no GPU the SpringBoard surfaces are never drawn: faking a display yields a black screen, and
copying the interface swap-surfaces has no pixel source. This corrects an earlier assumption,
carried from an iOS 14 precedent, that iOS software-renders the interface; that does not hold for
iOS 27.

The only pixels obtainable without a GPU are the kernel-drawn surfaces owned by the legacy
framebuffer class: the boot spinner, the system console, and the default framebuffer. Those are
CPU-drawn and can be copied to the scanout framebuffer the emulator already displays.

Bottom line for the display goal: the SpringBoard home screen is blocked by the absence of GPU
emulation, which is not feasible on this host, so that specific result is out of reach. What is
reachable and satisfies the "real framebuffer surface, not a synthetic painter" criterion is the
kernel's own drawn surface. A near-complete injected routine for that exists: hook the legacy
framebuffer swap entry and copy its surface into the scanout framebuffer via the kernel's
physical-copy helper. Two values still need a runtime probe to finalize, since the emulator debug
stub cannot break on kernel code: the copy helper's address and the default-framebuffer surface's
physical base, plus confirming the legacy swap path is exercised in this boot.

The coprocessor-mailbox result and goals one and two remain intact. This entry records the honest
ceiling: kernel-drawn pixels are reachable; the GPU-composited interface is not.

---

## GPU firmware maps to the same coprocessor stack; the real pixel path is forcing the boot console

Two parallel investigations landed.

The GPU. The AGX (G17) firmware coprocessor uses the exact same coprocessor and mailbox stack as
the display coprocessor. The forced-power-up routine we already proved transfers unchanged except
for the coprocessor name it gates on. Its device-tree node exists but lacks the compatible string
that binds the coprocessor driver, and the whole GPU accelerator side of the device tree is
absent, so bringing the GPU firmware mailbox to life needs a device-tree addition plus a mailbox
model, and even then it renders nothing without the accelerator, its page tables, the firmware
image, and ultimately the GPU hardware. It is the same shape as the display-coprocessor work, one
layer deeper, and it does not produce pixels. Recorded as buildable but lower priority.

The pixels. The only kernel virtual address that validly maps the scanout framebuffer is the one
the kernel itself creates for it; the physical aperture does not cover the framebuffer (it is
carved just above usable memory), which a direct test confirmed by faulting. That same
kernel-created mapping is where the kernel's own text/spinner console would draw. So the pixel
path is not copying a surface; it is forcing the kernel graphics console on, so the verbose boot
text and boot spinner paint the scanout directly. This also explains why the framebuffer is
blank: modern iOS suppresses the linear-framebuffer console in favor of the display coprocessor,
so nothing paints it. The next step is to find and flip that suppression so the kernel paints its
own boot output to the screen, which is real, kernel-drawn iOS pixels. Goals one and two and the
mailbox result remain intact.

---

## Final verdict on pixels: an architectural ceiling, not a missing patch

Forcing the kernel graphics console on does not work: it reaches a callback-iteration loop that
walks a display-callback registry and calls each entry. Guarding one bad entry only moves the
fault to the next; the entries are garbage of different shapes (misaligned, and aligned-but-not-
code). The registry is fundamentally uninitialized, because it is populated by the display
subsystem initialization that only the absent display driver performs. So the console cannot be
forced to paint without first bringing up the whole display driver state.

Every pixel path has now been tested and is blocked:

- Writing the framebuffer directly from kernel code faults, because the framebuffer is carved
  above usable memory and is outside the physical aperture the physmap covers.
- Copying the legacy framebuffer surface does not run, because that framebuffer class never
  attaches without the display coprocessor.
- Forcing the kernel graphics console iterates an uninitialized callback registry and crashes.
- The real display path needs the secure-world route object (absent) to arm its receive path,
  and, for the interface, the GPU.
- The GPU firmware coprocessor is forceable, but rendering needs the actual GPU hardware to
  execute shaders; no software implementation of it exists.

The conclusion is architectural: the iOS 27 interface is composited only by the GPU, which is not
emulatable on this host, and every kernel-drawn fallback is coupled to display-subsystem state
that only the absent display driver initializes. No iOS pixels are reachable here.

What stands: goals one and two are delivered and verified (the full interface stack boots
internally, writable data volume, multi-minute uptime), and the display coprocessor mailbox was
brought to life by our own injected kernel code, which is a genuine first even though it does not
render. This entry records the honest ceiling reached after exhausting every display path.
