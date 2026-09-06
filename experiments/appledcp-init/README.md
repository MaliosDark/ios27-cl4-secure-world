# AppleDCP init bring-up — analysis + patch design

Authorized security research (own machine). Goal: get the guest's IOMobileFramebuffer /
AppleDCP to open the AFK endpoint against our emulated DCP (`hw/arm/apple_dcp.c`) so
`[dcp] AFK INIT` fires and, after that, real display surfaces flow.

**Scope guard honored:** this is analysis + patch DESIGN only. Nothing here was built or
booted; the live `qemu-sptm` tree and `firmware/bootkc` were only *read*.

All scripts referenced live in `./scripts/` and run against
`/Users/maliosdark/darwin-vm/firmware/bootkc` using the capstone in
`/Users/maliosdark/vphone-cli/.venv`.

---

## 0. Kernelcache address model (how every address below was derived)

`firmware/bootkc` is a Mach-O arm64e **FILESET**. Boot slide in these runs is `0x20000000`,
so **static = runtime − 0x20000000**. Static vmaddr → file offset uses the top-level
segments (`scripts/kc.py map`):

| segment          | static vmaddr range                     | file offset |
| ---------------- | --------------------------------------- | ----------- |
| `__TEXT`         | `0xfffffff007004000..0xfffffff00700c000`| `0x0`       |
| `__PRELINK_TEXT` | `0xfffffff00700c000..0xfffffff007da0000`| `0x8000`    |
| `__DATA_CONST`   | `0xfffffff007da0000..0xfffffff0083b4000`| `0xd9c000`  |
| `__TEXT_EXEC`    | `0xfffffff008400000..0xfffffff00b354000`| `0x13fc000` |
| `__PRELINK_INFO` | `0xfffffff00b35c000..0xfffffff00b5dc000`| `0x4358000` |
| `__DATA`         | `0xfffffff00b5dc000..0xfffffff00b8cc000`| `0x45d8000` |
| `__LINKEDIT`     | `0xfffffff00b8cc000..0xfffffff00b990000`| `0x48c8000` |

Reproduce: `scripts/kc.py v2f <vmaddr>` / `dis <static>` / `disr <runtime>`.

**Fileset ownership** (`scripts/fileset.py <vmaddr>`, parses `LC_FILESET_ENTRY` + each kext's
inner segments). This is the single most important correction of this pass:

| static vmaddr        | owner (fileset entry)                | segment                                  |
| -------------------- | ------------------------------------ | ---------------------------------------- |
| `0xfffffff00ac9376c` | **com.apple.kernel** (base XNU)      | `__TEXT_EXEC 0xaa60000..0xb34c000`       |
| `0xfffffff00ac6e094` | **com.apple.kernel** (base XNU)      | `__TEXT_EXEC 0xaa60000..0xb34c000`       |
| `0xfffffff00b6c08b8` | **com.apple.kernel**                 | `__DATA 0xb630000..0xb768000`            |
| `0xfffffff0089ee530` | com.apple.driver.AppleDCP            | `__TEXT_EXEC 0x89ee530..0x89f6b70`       |
| `0xfffffff00a7a4f70` | com.apple.driver.RTBuddy             | `__TEXT_EXEC 0xa7a4f70..0xa7eaa74`       |

**Both crash sites are in BASE XNU, not in the AppleDCP or RTBuddy kexts.** The
`com.apple.driver.AppleDCP(...)@0xfffffff0289ee530->...` / `RTBuddy@0xfffffff02a7a4f70->...`
lines in the panic are just the *kexts present on the backtrace stack*; the faulting `pc`/`lr`
are base-kernel code. There is no top-level `LC_SYMTAB` (stripped), so everything below is
anchored on DT strings / semantic decode, not a symbol dump (per CLAUDE.md guardrails).

---

## 1. Reverse of the two crashes

### 1a. Crash B (`far=0xb1`) is the kernel PANIC LOG, **not** an AppleDCP state object — RETRACTION

Prior model (RESUME UPDATE 17) called `0xfffffff00b6c08b8` "a DCP STATE object pointer".
That attribution is wrong. Evidence:

The global is written **exactly once** in the whole kernel (`scripts/scan.py ea 0xfffffff00b6c0000 0x8b8` → the only WRITE):

```
0xfffffff00b2fbf78  fo=0x42f7f78  str x0, [x9, #0x8b8]      (x9 = &0xfffffff00b6c0000)
```

The enclosing function starts at **`0xfffffff00b2fbe78` (fo `0x42f7e78`)**. Decoded, it is the
XNU **pram / embedded-panic-log** setup (device_tree.c-adjacent). Its string anchors
(`scripts/kc.py` + string reads) are unambiguous:

```
0xfffffff00b2fbea0  bl 0xfffffff00b35a1d8   ; DT lookup, x1 -> "pram"                    -> w0
0xfffffff00b2fbea4  cmp w0, #1
0xfffffff00b2fbea8  b.ne 0xfffffff00b2fbfd4  ; BAIL (leaves global == 0)
0xfffffff00b2fbed8  bl 0xfffffff00b359fc4   ; DT get-property, x1 -> "reg"               -> w0
0xfffffff00b2fbedc  cmp w0, #1
0xfffffff00b2fbee0  b.ne 0xfffffff00b2fbfd4  ; BAIL
0xfffffff00b2fbef8  bl 0xfffffff00b35a1d8   ; DT lookup "/chosen":"embedded-panic-log-size"
0xfffffff00b2fbf00  b.ne 0xfffffff00b2fbfd4  ; BAIL
0xfffffff00b2fbf4c  bl 0xfffffff00ac64080   ; map the pram region (args region,size,6,3,0) -> x0
0xfffffff00b2fbf54  str x0, [..#0x8b0]       ; mirror
0xfffffff00b2fbf78  str x0, [..#0x8b8]       ; THE paniclog buffer pointer
0xfffffff00b2fbf7c  ldr w9, [x0]             ; validate region magic 'RCTB'/'CMHS'/'KNFU'...
```

Strings referenced (fo via `__TEXT` @0): `pram` (`0x70d075f`), `reg` (`0x70d0b65`),
`/chosen` (`0x70d0b77`), `embedded-panic-log-size` (`0x70d0764`), `device_tree.c`
(`0x70d0315`), `DeviceTree overflow…` (`0x70d02eb`). No AppleDCP driver looks these up.

The **consumer** at crash B (`0xfffffff00ac6e094`, fo `0x3c6a094`) reads that same global and
fills a panic header — it copies the **kernel version banner** (`"Darwin Kernel Version
27.0.0…T8140"`, `0x7044583`) into `[buf+0xd9]` with `w2=0x200`, stores a `double` (uptime)
at `[buf+0xb1]`, sets flag bits from a bitmask arg (`w22`), and references
`"Warning: clock is locked…"` (`0x7068bd3`). That is `PE`/`debug_buf` panic-header code, run
**only on the panic path** (baseline boots 209 lines and never triggers it).

**Conclusion:** `far=0xb1` is a *panic-time double fault*: something upstream panics, XNU
enters the panic logger, and the logger dereferences `0xfffffff00b6c08b8` which is `NULL`
because the pram setup (`0xb2fbe78`) **bailed at one of its DT gates** (or the `0xac64080` map
returned 0). The DT *does* contain a `pram` / `APL,OSXPanic` node (`strings firmware/dtree_nr2`
shows `pram`, `APL,OSXPanic`, `flush-cache-on-panic`, …), so the most likely cause is that the
pram physical region named by its `reg` is **not backed by RAM in this QEMU machine**, so the
map fails and the pointer is left null. Crash B therefore *masks* the real AppleDCP panic.

### 1b. Crash A (`PC alignment`) is a base-kernel indirect callback-list walk with a garbage entry

Faulting function **`0xfffffff00ac9376c` (fo `0x3c8f76c`)**, base XNU. Full decode
(`scripts/kc.py dis 0xfffffff00ac9376c 60`):

```
0xac9376c pacibsp ; prologue, loads __stack_chk_guard (adrp 0xb658000)
0xac9379c ldr  x8, [x2, #8]      ; x8 = entry->callback   (x2 = table arg #3)
0xac937a0 cbz  x8, done          ; null callback -> clean exit (0xac937dc)
loop:
0xac937bc ldr  w0, [x21, #0x20]  ; w0 = self->field_0x20  (x21 = arg #1 = self)
0xac937c0 mov  x17, #0xba5       ; PAC modifier
0xac937c4 blraa x8, x17          ; call entry->callback(w0)   <-- FAULTS
0xac937c8 cmp  x24, x0           ; x24 = arg #2 (match key) vs return value
0xac937cc b.eq matched(0xac93810)
0xac937d0 ldr  x8, [x22, #0x20]  ; next entry callback (stride 0x18, +8)
0xac937d4 add  x22, x22, #0x18
0xac937d8 cbnz x8, loop
```

Shape: a **stride-0x18 table of `{key@+0, cb@+8, cb2@+0x10}`**, iterated; each `cb` is a
PAC-A pointer signed with discriminator `0xba5`; on the entry whose `cb` returns the match
key, the `matched` path zeroes a large stack struct and calls `cb2` with discriminator
`0x3b24`. This is a generic "ask each registered handler, first that claims the id wins"
dispatcher. `0xba5` is **not** subsystem-unique (70 sign/call sites across base XNU —
`scripts/scan.py`-style scan), so it is a shared callback type, not a DCP marker.

`0xac9376c` has **no direct `bl` caller** anywhere in `__TEXT_EXEC`
(`scripts/scan.py bl 0xfffffff00ac9376c` → none) — it is reached indirectly (installed as a
function pointer / vtable slot and `blr`'d).

The fault: `x8 = [x2+8]` is **non-null but not correctly signed** (`blraa` yields the
misaligned `pc 0x…459`). With `DARWIN_NOPAC=1` it still crashes, so it is not a PAC-strip
problem — the *table entry itself is garbage*. A never-populated BSS table would be all-zero →
`cbz x8` → clean exit, no crash. A **garbage non-zero** `cb` means the table is
stale/uninitialised heap or a partially-built structure — i.e. an init step that should have
filled valid entries **before** this walk did not run.

### 1c. Why the init step didn't run — the device-tree gate

The DT `iop-dcp-nub` node carries `routes` (→ secure exclave mailbox
`com.apple.service.SecureRTBuddyDCP`) and `no-firmware-service`. Empirically (RESUME UPDATE
17, `dt_fixup.py`):

| DT variant   | `routes` | `no-firmware-service` | observed                                    |
| ------------ | :------: | :-------------------: | ------------------------------------------- |
| `dtree_nr2`  |   off    |        **kept**       | AppleDCP runs, then **crash A** (garbage cb)|
| `dtree_norm` |   off    |        removed        | **crash B** (`far=0xb1`, paniclog null)     |
| `dtree_nr`   |   off    |        removed        | same `far=0xb1`                             |

Interpretation, consistent with all evidence:
- With `no-firmware-service` **kept**, AppleDCP takes the *secure/exclave firmware* branch. It
  expects the secure-world DCP service to register its transport handlers (populate the table
  walked at `0xac9376c`) and to hand over firmware. The secure world is absent, so those
  handlers are never installed; AppleDCP proceeds into the dispatch walk over a
  stale/garbage list → crash A. **It never reaches the point of writing `CPU_CONTROL RUN`**,
  so our emulated ASC mailbox never even gets `HELLO` (RESUME UPDATE 12/17: zero mailbox
  traffic, no `[dcp] AFK INIT`).
- With `no-firmware-service` **removed**, AppleDCP takes the normal-world firmware-service
  branch, which faults elsewhere and panics; the panic logger then double-faults on the null
  pram buffer → `far=0xb1` (crash B), which *hides* the underlying AppleDCP error.

**Root cause (both):** AppleDCP's init is waiting on the secure-world DCP transport to seed its
handler table and state; neither DT variant provides a path where AppleDCP populates the table
itself and boots the coprocessor over the plain ASC mailbox we emulate. The exact branch that
selects secure-vs-normal firmware inside the AppleDCP kext (`0x89ee530..0x89f6b70`) was **not**
pinned this pass (see reveal procedure in §2/§4) — but its *effect* is fully characterised, and
the highest-value next action does not require pinning it (§4 step 1 unmasks the real panic).

---

## 2. Minimal interventions to reach `[dcp] AFK INIT` (ordered by preference)

### (a) Device-tree first — no kernel patch

1. **Back the pram region so crash B stops masking crash A.** The `pram`/`APL,OSXPanic` node
   exists in the DT but its `reg` physical range is (almost certainly) not RAM-backed in the
   `-M darwin` machine, so the paniclog map (`0xac64080`) fails and `0xfffffff00b6c08b8` stays
   null. Add a RAM region covering the pram `reg` (QEMU side, `hw/arm/darwin.c`, same pattern
   as the framebuffer carve-out `init_framebuffer`), **or** rewrite the `pram` `reg` in the DT
   (`dt_fixup.py`, new `PRAM_BACK=1` knob) to point at an existing reserved RAM range.
   *Expected observable:* the next panic prints the **real** AppleDCP panic string on serial
   instead of `Kernel data abort … far 0xb1`. This alone converts crash B into readable
   diagnostics and is the single most useful step.

2. **Keep `dtree_nr2` (`DCP_NO_ROUTES=1`, `no-firmware-service` KEPT)** as the base — it already
   removes the secure-route wait. Then probe DT properties that flip AppleDCP onto a
   self-firmware path. Candidates to try (each via `EXTRA_NODES` / a new `dt_fixup.py` toggle),
   observing whether `CPU_CONTROL RUN` is written (→ `[rtkit:dcp] CPU_CONTROL RUN` in QEMU):
   - drop `no-firmware-service` **and** add `region-base`/`region-size` (`DCP_REGION=1`) so the
     nub looks like a normal firmware-loading RTKit IOP (matches `iop-ans-nub`);
   - set `DCP_POWER_MODE=power-managed` (so RTBuddy powers the IOP itself);
   - ensure endpoint `0x24` is advertised (already emulated in `apple_dcp.c`).
   *Expected observable:* if any combination makes RTBuddy(DCP) boot the coprocessor,
   `[rtkit:dcp] CPU_CONTROL RUN` → `HELLO` → `EPMAP` → `STARTEP 0x24` → `[dcp] AFK INIT`.

### (b) Small semantic kernel patch (only if DT cannot flip the path)

Purpose: make AppleDCP take the transport-up path without the secure world, i.e. neutralise
the secure-firmware gate so it registers its own handlers and boots the mailbox coprocessor.
Per CLAUDE.md kernel-patch guardrails: no hardcoded bytes; matches derived from capstone decode;
replacement bytes from the project's Keystone helpers (`asm()`, `NOP`, `MOV_W0_0`, …).

- **Reveal the gate before patching.** With the pram region backed (step a1), boot `dtree_nr2`
  and read the real AppleDCP panic. Symbolicate its `pc` inside the AppleDCP kext
  (`0x89ee530..0x89f6b70`) via `scripts/fileset.py`, disassemble the enclosing function, and
  find the branch of the form `bl <get-secure-service>; cbz/cbnz x0, <secure-only path>` (or a
  DT-property test of `no-firmware-service`). That branch is the gate.
- **Patch intent (branch gate only):** turn the "secure service present?" test so it takes the
  **normal-world** path — i.e. replace the conditional branch that jumps into the secure-only
  init with an unconditional fall-through into the self-init path (Keystone `B`), or NOP the
  early-return that skips handler registration. Log the site as `vmaddr / file-offset /
  before→after` and **also update `research/0_binary_patch_comparison.md`** (project rule).
- **Do NOT** patch the dispatcher `blraa` at `0xac937c4` to skip (RESUME `bootkc.dcptest` did
  this: `blraa x8 → mov x0,xzr`). That only removed the symptom and exposed crash B; it does
  not make AppleDCP register real handlers, so AFK still never opens. It is a diagnostic, not a
  fix.

### (c) QEMU-side device stub (complementary, not a substitute)

`DARWIN_RTKIT=1` already brings the DCP ASC mailbox live (`apple_rtkit.c` +
`apple_dcp_attach`, mailbox `0x412E00000`, endpoints `0x23/0x24/0x25`, `hw/arm/darwin.c`
`init_rtkit_dcp`). The mailbox only starts (`apple_rtkit_boot` → `HELLO`) when the guest writes
`ASC_CPU_CONTROL_RUN` (`apple_rtkit.c` `rtkit_write`). Because AppleDCP crashes before that
write, the mailbox is currently dead code. So the QEMU side is *ready and waiting*; the blocker
is purely getting AppleDCP past its init (a/b above). One optional QEMU aid: `DARWIN_DISP=…`
register stubs so any disp0/dcp-expert MMIO AppleDCP touches during self-init don't fault
(RESUME notes `DARWIN_DISP=all` + DART + PMGR broke early boot, so add stubs selectively).

---

## 3. Next stage — after AFK is up, decoding the guest's real surface

Once `[dcp] AFK INIT` fires, `dcp_ep_handler` in `hw/arm/apple_dcp.c` already drives the AFK
ring handshake to "transport up":

`RBEP_INIT → INIT_ACK + GETBUF` → guest `GETBUF_ACK` gives `s->bfr_dva` (the shared ring
buffer, `GETBUF_ACK_DVA_MASK` = GENMASK(47,0)) → we describe TX/RX rings (`INIT_TX`/`INIT_RX`,
first/second halves of the 0x1000 buffer) → `START` → guest `START_ACK` → `s->started`.

The gap: **`RBEP_RECV` is only logged**, never read. That is where IOMFB/EPIC RPC arrives:

- On `RBEP_RECV`, the guest has written an EPIC message into the **TX ring at `s->bfr_dva`**
  (first half; RX is second half at `+0x800`). Add a reader that `address_space_read`s the ring
  head from guest memory at `bfr_dva`, parses the AFK ring header (read/write pointers), and
  decodes the EPIC/OSObject-serialised IOMFB call. Mirror roles from Asahi
  `drivers/gpu/drm/apple/afk.c` + `dcp/` (we are the coprocessor; their AP-side send == our
  receive).
- The IOMFB calls to decode for a surface:
  - **swap_start / swap_submit** (`IOMobileFramebuffer::swap_submit_dcp`): carries the
    surface's **IOSurface descriptor** — the DMA/`iova` base of the pixel buffer, `stride`
    (bytes/row), `width`, `height`, and pixel format. This is the address our scanout must read
    instead of the synthetic frame.
  - **set_matrix / setup_video_limits / set_parameter**: mode/size confirmation.
- Concretely in `apple_dcp.c`:
  1. Give `AppleDCPState` a parsed-surface struct `{uint64_t surf_iova; uint32_t w,h,stride,fmt;}`.
  2. In `RBEP_RECV`, read the TX ring at `s->bfr_dva`, walk EPIC sub-messages, and on the
     swap/surface-register call fill that struct; set `s->surface_live = true`.
  3. In `dcp_paint`, when `surface_live`, replace the synthetic renderer with
     `address_space_read(&address_space_memory, surf_iova, …)` of `stride*h` bytes and blit
     (format-convert if needed) into `fb_base` — the DarwinFB console already scans out
     `fb_base` (`darwin.c` `init_framebuffer` / `darwin_fb_update`).
  4. Send the matching AFK **completion/ack** back on the RX ring so the guest's swap completes
     and it queues the next frame (otherwise IOMFB stalls after one surface).

Note: the surface iova is a **DART/IOMMU** address; if `DARWIN_DART` mapping is not modeled for
DCP, treat `surf_iova` as a guest-physical/identity address first and verify the pixels look
right, then add DART translation if it is remapped.

---

## 4. Ordered "try this" plan

Each step: **what / where / expected observable.**

1. **Back the pram region (unmask the real panic).**
   *What:* add RAM behind the DT `pram`/`APL,OSXPanic` `reg`, or repoint that `reg` at existing
   reserved RAM. *Where:* `hw/arm/darwin.c` (RAM carve-out like `init_framebuffer`) or a new
   `PRAM_BACK=1` in `dt_fixup.py`. *Expected:* on the AppleDCP fault, serial prints the **real**
   AppleDCP panic (string + `pc` in `0x89ee530..0x89f6b70`) instead of
   `Kernel data abort … far 0x00…b1`. **Do this first — everything else keys off the revealed panic.**

2. **Symbolicate & reveal the AppleDCP secure-firmware gate.**
   *What:* take the panic `pc`, `scripts/fileset.py <runtime-0x20000000>` to confirm it's in the
   AppleDCP kext, `scripts/kc.py dis` the enclosing function, find `bl <get-service>; cbz/cbnz →
   secure-only` or the `no-firmware-service` property test. *Expected:* a single named branch
   (vmaddr + file offset) that chooses secure vs normal-world DCP firmware/handlers.

3. **DT flip attempt (no patch).**
   *What:* base `DCP_NO_ROUTES=1` (keep `no-firmware-service`), then iterate the §2(a)2 toggles
   (`DCP_REGION=1`, drop `no-firmware-service`, `DCP_POWER_MODE=power-managed`) with
   `DARWIN_RTKIT=1 DARWIN_FB=1`. *Where:* `dt_fixup.py`. *Expected:* `[rtkit:dcp] CPU_CONTROL
   RUN` appears (guest booted the coprocessor). If it does, watch for `HELLO → EPMAP → STARTEP
   0x24 → [dcp] AFK INIT`.

4. **If DT can't flip it: minimal branch-gate patch.**
   *What:* at the revealed branch (step 2), force the normal-world path (unconditional `B` into
   self-init, or NOP the early-return that skips handler registration). *Where:* new patcher in
   `darwin-vm/` following `patch_rtbuddy_*` style (capstone match, Keystone `asm()`/`NOP`
   replacement, no hardcoded bytes). *Expected:* AppleDCP completes init, registers handlers
   (dispatcher `0xac9376c` now walks valid entries), and writes `CPU_CONTROL RUN` →
   `[dcp] AFK INIT`. **Update `research/0_binary_patch_comparison.md`.**

5. **AFK transport up → confirm surface traffic.**
   *What:* nothing new — `apple_dcp.c` already answers `INIT/GETBUF/INIT_TX/INIT_RX/START`.
   *Expected:* `[dcp] AFK transport up on endpoint 0x24` then `[dcp] AFK RECV` when the guest
   posts an IOMFB message.

6. **Decode the surface and scan it out.**
   *What:* implement §3 — read the TX ring at `bfr_dva` on `RBEP_RECV`, parse the swap/surface
   call for `{iova,stride,w,h,fmt}`, blit guest surface → `fb_base`, ack on the RX ring.
   *Where:* `hw/arm/apple_dcp.c`. *Expected:* the DarwinFB console shows the guest's **real**
   IOMFB surface (SpringBoard/boot UI) rather than the synthetic bring-up frame, and swaps keep
   flowing (no one-frame stall).

---

## 5. Scripts (in `./scripts/`, use `/Users/maliosdark/vphone-cli/.venv`)

- `kc.py` — segment map + static/runtime disassembly + v2f/f2v + adrp/add xref.
  `kc.py dis 0xfffffff00ac9376c 60`, `kc.py disr <runtime> 40`, `kc.py v2f <v>`.
- `fileset.py` — map a static vmaddr to its owning `LC_FILESET_ENTRY` kext + segment.
  `fileset.py 0xfffffff00ac9376c 0xfffffff00b6c08b8`.
- `scan.py` — resyncing scanner over `__TEXT_EXEC`. `scan.py ea <page> <disp>` finds all
  str/ldr to a global (adrp+disp aware; **note** capstone returns the adrp immediate signed —
  the script masks to unsigned 64-bit). `scan.py bl <target>` finds direct callers.
- `sym.py` — LC_SYMTAB symbolicator (this kernelcache is stripped at top level, so it returns
  nothing here; kept for kernelcaches that do carry a symtab).

### Cited sites (vmaddr / file offset / fileset)

| what                                   | static vmaddr        | file offset | fileset            |
| -------------------------------------- | -------------------- | ----------- | ------------------ |
| crash A dispatcher (fn start)          | `0xfffffff00ac9376c` | `0x3c8f76c` | com.apple.kernel   |
| crash A faulting `blraa x8,#0xba5`     | `0xfffffff00ac937c4` | `0x3c8f7c4` | com.apple.kernel   |
| crash B paniclog consumer (fn start)   | `0xfffffff00ac6e094` | `0x3c6a094` | com.apple.kernel   |
| crash B faulting `stur d0,[x8,#0xb1]`  | `0xfffffff00ac6e104` | `0x3c6a104` | com.apple.kernel   |
| paniclog buffer global (`+0x8b8`)      | `0xfffffff00b6c08b8` | `0x46bc8b8` | com.apple.kernel `__DATA` |
| paniclog/pram setup fn (writes global) | `0xfffffff00b2fbe78` | `0x42f7e78` | com.apple.kernel   |
| ↳ the one write of the global          | `0xfffffff00b2fbf78` | `0x42f7f78` | com.apple.kernel   |
| ↳ DT "pram" gate / "reg" gate          | `0xfffffff00b2fbea0` / `…ed8` | `0x42f7ea0` / `…ed8` | com.apple.kernel |
| pram region map helper                 | `0xfffffff00ac64080` | `0x3c60080` | com.apple.kernel   |
| DT lookup / get-property helpers       | `0xfffffff00b35a1d8` / `0xfffffff00b359fc4` | `0x43561d8` / `0x4355fc4` | com.apple.kernel |
| AppleDCP kext `__TEXT_EXEC`            | `0xfffffff0089ee530..0x89f6b70` | `0x19ea530..0x19f2b70` | com.apple.driver.AppleDCP |

QEMU side (read-only reference, live tree — do not edit here):
`hw/arm/apple_dcp.c` (`dcp_ep_handler`, `RBEP_*`, `bfr_dva`, `dcp_paint`, `apple_dcp_attach`),
`hw/arm/apple_rtkit.c` (`rtkit_write`→`ASC_CPU_CONTROL_RUN`→`apple_rtkit_boot`, `handle_a2i`),
`hw/arm/darwin.c` (`init_rtkit_dcp`, `init_framebuffer`, mailbox `0x412E00000`).
