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
