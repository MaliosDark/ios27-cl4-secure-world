# AppleDCP crash A — root-cause CORRECTION + fix design

Authorized security research on the user's own machine. Analysis + patch **design** only.
Nothing here was built or booted; `firmware/bootkc`, `qemu-sptm/`, `dt_fixup.py` were only
*read*. Scripts in `./scripts/`, run against `/Users/maliosdark/darwin-vm/firmware/bootkc`
with the capstone in `/Users/maliosdark/vphone-cli/.venv`.

Goal (unchanged): get the iOS 27 (iPhone17,3 / t8140) guest's AppleDCP / IOMobileFramebuffer
to open the AFK endpoint against the emulated DCP (`hw/arm/apple_dcp.c`) so `[dcp] AFK INIT`
fires and real display surfaces flow.

Address model (same as `appledcp-init`): `bootkc` is an arm64e Mach-O **FILESET**, boot slide
`0x20000000`, so **static = runtime − 0x20000000**. `scripts/kc.py map` prints the top-level
segment→file-offset table; `scripts/fileset.py <static>` names the owning `LC_FILESET_ENTRY`.

---

## TL;DR — the prior model was wrong; crash A is a base-XNU error-decoder overrun

The `appledcp-init` analysis (and RESUME UPDATE 15/17) modelled crash A as *"AppleDCP took the
secure/exclave-firmware branch, never populated a handler table, and the dispatcher at
`0xfffffff00ac9376c` walked a stale/garbage heap list."* **That is incorrect.** This pass pins
every address and overturns it:

- The function at `0xfffffff00ac9376c` is a **base-XNU generic table-walk dispatcher**, and the
  table `x2` it walks is a **compile-time `const` array in `__DATA_CONST`**
  (`0xfffffff007de2338`), not a runtime-populated AppleDCP object. Its entries are valid,
  correctly chained-fixup-signed function pointers. Nobody "fails to fill" it — it is static
  data. (Task 1.)
- The enclosing caller is XNU **`sleh.c`** (string `"sleh.c"` @ `0xfffffff007067a17`,
  `"Panic lockdown initiated for platform error @%s:%d"` @ `0xfffffff007067a3e`) — the
  synchronous-exception low-level handler. The specific caller path is the **external-abort /
  platform-error** arm.
- The `blraa` fault target `0xfffffff02706e459` (static `0xfffffff00706e459`) is **not a
  callback at all — it is a string literal**, `" (bad cmd)"`, sitting in the `const`
  string-pointer pool **immediately after** the 7-entry `hwerr_type_*` decoder table. The walk
  **overran the 7 valid entries** and `blraa`'d the first string pointer → branch to an
  odd/misaligned address → **"PC alignment exception from kernel."**

So crash A is a **secondary crash**. The **primary** event is a **synchronous external abort
(SEA)**: AppleDCP's init touched an **MMIO register that is not backed in the QEMU `-M darwin`
machine**; the bus returned an abort; XNU `sleh` ran its platform-error / hardware-error
decoder to *name* the error; the Apple error-syndrome the decoder matches against is
unmodelled by QEMU's CPU (so no `hwerr_type_*` row matches); the walk fell off the end of the
const table and called a string as a function.

**Consequence for the fix:** no kernel branch-patch can make AppleDCP boot, because the
aborting MMIO **read still returns no data** — AppleDCP cannot get the register value it needs.
The only real fix is to **back the MMIO** (QEMU/DT side), exactly as the pram fix backed the
panic-log region. A kernel patch can at most *unmask* the primary SEA's fault address. This is
the single most important correction of this pass.

---

## 1. WHO fills the callback table `x2` walked at `0xfffffff00ac9376c` (Task 1)

**Answer: no runtime registrar. `x2` is a `const` compile-time table in `__DATA_CONST`; the
"garbage callback" is a string pointer reached by a table overrun.**

### 1a. The dispatcher (`scripts/kc.py dis 0xfffffff00ac9376c`)

`0xfffffff00ac9376c` (fo `0x3c8f76c`, `com.apple.kernel __TEXT_EXEC`) — a generic
"poll each registered handler; first that claims the id wins" walk:

```
0xac9379c  ldr   x8, [x2, #8]        ; x8 = entry[0].cb          (x2 = table, arg#3)
0xac937a0  cbz   x8, done            ; null cb -> clean exit
loop (0xac937bc):
0xac937bc  ldr   w0, [x21, #0x20]    ; w0 = self->field_0x20     (x21 = arg#1 = self)
0xac937c0  mov   x17, #0xba5         ; PAC discriminator (plain, not addr-diversified)
0xac937c4  blraa x8, x17             ; call cb(w0)               <-- FAULTS on overrun
0xac937c8  cmp   x24, x0             ; x24 = arg#2 (match key) vs cb's return
0xac937cc  b.eq  matched (0xac93810) ; on match -> zero 0xd0 struct, call cb2 (disc 0x3b24)
0xac937d0  ldr   x8, [x22, #0x20]    ; next entry cb  (stride 0x18, cb at +8)
0xac937d4  add   x22, x22, #0x18
0xac937d8  cbnz  x8, loop            ; stop only when a cb slot is 0
```

Entry layout: `{key@+0, cb@+8, cb2@+0x10}`, stride `0x18`. `cb` is signed PAC-IA disc `0xba5`,
`cb2` PAC-IA disc `0x3b24`. Neither discriminator is subsystem-unique (89 call / 71 sign sites
for `0xba5`; `scripts/disc_fast.py 0xba5`), so they do **not** mark AppleDCP.

The prior claim "no direct `bl` caller" was a `scan.py` desync artefact. A **definitive raw
scan** (`scripts/rawbl.py 0xfffffff00ac9376c`) finds **4 direct callers**, all inside one
function:

```
0xfffffff00ac9304c  0xfffffff00ac93104  0xfffffff00ac9312c  0xfffffff00ac93154   (BL -> 0xac9376c)
```

### 1b. The caller, and what `x2` really is

Enclosing function **`0xfffffff00ac92f08`** (fo `0x3c8ef08`). It reads `mpidr_el1`,
`tpidr_el1`, and a battery of Apple implementation-defined error-status registers
(`s3_4_c15_c0_0..3`, `s3_3_c15_c0/c2_0`, `s3_5_c15_c0_5`, `s3_3_c15_c8/c9/c10_0`), builds an
on-stack syndrome descriptor at `sp+0x68`, and calls the dispatcher four times — once per
error-register group — each with a **different `const` table**. For the group that crashes
(`x22 = mrs s3_5_c15_c0_5`, string label `"DPC"` @ `0xfffffff00706d2b0`):

```
0xac93030  adrp x2, 0xfffffff007de2000 ; add x2,#0x338  -> x2 = 0xfffffff007de2338  (the table)
0xac9303c  adrp x3, 0xfffffff00706d000 ; add x3,#0x2b0  -> x3 = "DPC"
0xac93044  mov  x4, x22                ; x4 = the s3_5_c15_c0_5 syndrome value
0xac9304c  bl   0xfffffff00ac9376c
```

`x2 = 0xfffffff007de2338` is in **`__DATA_CONST`** (`fileset.py` → `com.apple.kernel
__DATA_CONST`) — a **read-only compile-time table**, resolved at load by chained fixups. Dump
it with `scripts/hwerr_table.py`:

```
+0x000 hwerr_type_pio_locked_reg        cb=0xfffffff00ac94010 auth=1 disc=0x0ba5   valid
+0x018 hwerr_type_amx_corewfi_amx_vld   cb=0xfffffff00ac94004 auth=1 disc=0x0ba5   valid
+0x030 hwerr_type_lose_lock             cb=0xfffffff00ac93ff8 auth=1 disc=0x0ba5   valid
+0x048 hwerr_type_incpl_epoch           cb=0xfffffff00ac93fec auth=1 disc=0x0ba5   valid
+0x060 hwerr_type_time_backward         cb=0xfffffff00ac93fe0 auth=1 disc=0x0ba5   valid
+0x078 hwerr_type_thrtl_unsafe          cb=0xfffffff00ac93fd4 auth=1 disc=0x0ba5   valid
+0x090 hwerr_type_mtraccesslock         cb=0xfffffff00ac93fc8 auth=1 disc=0x0ba5   valid
+0x0a8  (addr map hole/size mis-match)  cb=0xfffffff00706e459 auth=0 disc=0x0000   << STRING POOL (overrun)
+0x0c0  (bad mask)                      cb=0xfffffff00706e676 auth=0 disc=0x0000   << STRING POOL
```

The table is **exactly 7 valid `hwerr_type_*` entries**. Right after it (`+0xa8`) begins a
separate `const` array of **error-suffix strings** — plain rebase pointers (auth=0), not
callbacks. `[+0xa8].cb = 0xfffffff00706e459` is the string **`" (bad cmd)"`**, which equals the
panic `pc` bit-for-bit. So on the crashing iteration `x8 = [table + 0xa8 + 8] = 0x…0706e459`
(non-zero → `cbnz` keeps looping), and `blraa x8,#0xba5` branches to it → PC-alignment fault.

**Why the overrun:** the loop terminates only on `cb == 0` (a null slot) *or* on a match
(`cmp x24,x0; b.eq`). On real hardware one of the 7 `hwerr_type_*` `decode_fn`s returns the
match key and the loop exits early. On the QEMU CPU the Apple error-syndrome registers are
unmodelled (return 0 / garbage), **no `hwerr_type` matches**, and there is no null slot before
the string pool → the walk overruns → crash. This will happen for **any** unclaimed-MMIO abort
on this machine, not just DCP's.

`scripts/`: `disc_fast.py` (disc-immediate sign/call sites), `rawbl.py` (definitive raw BL/B
xref), `addr_taken.py` + `chained.py` (LC_DYLD_CHAINED_FIXUPS resolver — proves **no** pointer
anywhere in the image targets `0xac9376c`; it is reached only by those 4 local `BL`s),
`hwerr_table.py` (the table dump above).

---

## 2. The primary exception: a synchronous external abort in `sleh.c` (Task 2, reframed)

There is **no AppleDCP "secure-vs-normal firmware" branch involved in this crash.** The crash
frame is entirely base XNU (`fileset.py` on every site → `com.apple.kernel`). The relevant
decision is in **`sleh` (`0xfffffff00ac6548c`, fo `0x3c6148c`)**, the synchronous-exception
handler:

```
0xac654b8  mov  x20, x1              ; x20 = ESR_EL1  (exception syndrome)
0xac654bc  mov  x19, x0             ; x19 = arm_saved_state (exception frame)
            ; x23 = arg#3 = FAR_EL1 (fault address)
0xac654d0  lsr  w25, w20, #0x1a      ; w25 = EC = ESR[31:26]  (exception class)
...
```

The arm that calls the hwerr decoder is the **external-abort filter** at
`0xfffffff00ac65ab4..0xac65ae4` (fo `0x3c61ab4..`):

```
0xac65ab4  and   w8, w20, #0x3f      ; w8 = ESR ISS xFSC[5:0]  (fault status code)
0xac65ab8  cmp   w8, #0x1f
0xac65abc  b.hi  0xac65bf8           ; xFSC > 0x1f -> not this path
0xac65ac0  mov   w9, #1
0xac65ac4  lsl   w9, w9, w8          ; w9 = 1 << xFSC
0xac65ac8  mov   w10, #-0x1cff0000   ; = 0xE3010000  (mask of external-abort FSCs:
0xac65acc  tst   w9, w10             ;   bits {16,24,25,29,30,31})
0xac65ad0  b.eq  0xac65bf8           ; not an external abort -> skip
0xac65ad4  mov   x0, x19             ; else: it IS an external/platform abort ->
0xac65ad8  mov   x1, x23             ;   x1 = FAR
0xac65adc  mov   w2, #1
0xac65ae0  mov   x3, x20
0xac65ae4  bl    0xfffffff00ac92f08  ; -> hwerr decoder (which overruns -> crash A)
```

The mask `0xE3010000` selects the **external-abort family of Data/Instruction Fault Status
Codes** (SEA and SEA-on-translation-walk). i.e. `sleh` reached the hwerr decoder **because a
load/store returned an external abort** — the signature of a read/write to **MMIO that the
QEMU machine does not back**. The faulting address is `FAR_EL1` = `x23` (arg to
`0xac6548c`; also `x1` into the decoder at `0xac65ad8`). AppleDCP's coprocessor-bring-up
touches a DCP register block that is not mapped → SEA → this path → overrun.

There are two other decoder callers (`0xfffffff00ac6829c`, `0xfffffff00ac689e4`) for the other
SEA sub-cases; all three funnel into the same overrunning decoder.

### Reveal the exact faulting MMIO address (do this first — it names the fix target)

`FAR_EL1` is not printed because the hwerr overrun pre-empts `sleh`'s normal abort panic. Two
ways to recover it, no live-tree edits required beyond flags:

1. **QEMU log (preferred, zero patching):** boot the existing repro with
   `-d unimp,guest_errors` (and `mmu` if wanted). `create_unimplemented_device` and the
   unassigned-access path log the address of the touched region at the instant of the abort —
   that address (minus `iobase`) is the DCP register block AppleDCP hit. This directly names
   which `arm-io/*` node to back in §3.
2. **Diagnostic kernel patch (optional):** neuter the external-abort→hwerr call so `sleh`
   falls through to its normal abort panic, which prints `far`. Guardrail-compliant
   (Keystone-backed, semantic anchor, no hardcoded bytes):
   - Anchor: in `sleh` (`0xac6548c`), the unique `BL 0xfffffff00ac92f08` at
     **`0xfffffff00ac65ae4` (fo `0x3c61ae4`)** guarded by the external-abort `tst`+`b.eq` at
     `0xac65ac8/0xac65ad0`.
   - Patch intent: replace the guard `b.eq 0xac65bf8` at **`0xfffffff00ac65ad0` (fo
     `0x3c61ad0`)** with an **unconditional `B 0xfffffff00ac65bf8`** (Keystone
     `asm("b #imm")`), so the hwerr decode is never entered and the normal panic prints `far`.
     *This is diagnostic only — it does not let AppleDCP boot.*

---

## 3. Minimal fix design (Task 3) — back the MMIO; do NOT patch the kernel branch

Ordered by preference. The controlling fact: **the aborting access must return data**, so the
fix has to be on the machine/DT side; a kernel patch cannot synthesize the register value.

### (a) Device-tree flags — none of the existing `DCP_*` options fix *this* stage

`dt_fixup.py`'s `DCP_NO_ROUTES` / `DCP_DROP_NOFWSVC` / `DCP_NORMALIZE` / `DCP_REGION` /
`DCP_POWER_MODE` all address the **earlier** secure-route / firmware-service handshake
(the `far=0xb1` and RTBuddy-start problems) — a stage this boot has already **passed** with
`dtree_nr2` (`DCP_NO_ROUTES=1`, `no-firmware-service` kept). None of them maps or changes an
MMIO region, so none can stop the SEA. Keep `dtree_nr2_pram` (pram backed, UPDATE 26) as the
base; there is no DT-property-only flip for crash A.

### (b) QEMU MMIO backing — the real fix

`hw/arm/darwin.c` already has the exact mechanism: **`init_display_stub()`** (≈ line 1189)
maps display-stack register ranges as **`create_unimplemented_device`** (RAZ/WI, logs under
`-d unimp`, **never aborts**), gated by `DARWIN_DISP` as a **substring filter**:

```
nodes[] = { arm-io/disp0, arm-io/dcp, arm-io/dcp0-expert,
            arm-io/dart-disp0, arm-io/dart-dcp, arm-io/display-crossbar0 }
DARWIN_DISP=all|1  -> stub all;  else substring-match one node (for bisecting)
```

RESUME UPDATE 17 found `DARWIN_DISP=all` + `DARWIN_DART` + `DARWIN_PMGR` broke early boot
(29 lines) — because the **DARTs** and PMGR have real semantics that a dumb RAZ/WI stub
violates. The display **register** blocks (`disp0`, `dcp`, `dcp0-expert`) do not have that
problem. So:

**Fix:** run the existing repro plus a **selective** display stub — the node named by the FAR
from §2. Concretely:

```
DARWIN_RTKIT=1 DARWIN_FB=1 DARWIN_DISP=dcp0-expert \
  qemu ... -bootkc firmware/bootkc  -dtree firmware/dtree_nr2_pram ...
```

Bisect order (most→least likely to be what AppleDCP pokes during ASC bring-up):
`dcp0-expert` → `dcp` → `disp0`. **Do not** add `dart-*` here (that is what broke boot).
Because the DT already advertises these nodes, IOKit matches them; the stub only needs to keep
the bus from aborting. Expected observable: the SEA disappears, AppleDCP finishes writing
`ASC_CPU_CONTROL_RUN`, and QEMU prints `[rtkit:dcp] CPU_CONTROL RUN` → `HELLO` → `EPMAP` →
`STARTEP 0x24` → **`[dcp] AFK INIT`** (`apple_dcp.c:113`).

If a stubbed RAZ/WI register returns a value AppleDCP rejects (e.g. it polls a status bit that
must read back non-zero), promote that one node from `create_unimplemented_device` to a small
`memory_region_init_io` handler that returns a plausible constant (mirror the `pmgr_ops` /
`asc_ops` pattern already in `darwin.c`). Identify which bit by re-reading the `-d unimp` trace
for the offset AppleDCP spins on.

### (c) Kernel patch — explicitly NOT the boot fix

The only guardrail-compliant kernel patch here is the **diagnostic** one in §2.2 (force
`sleh`'s external-abort guard to skip the hwerr decode so `far` prints). Patching the
dispatcher `blraa` (as `bootkc.dcptest` did) or bounding the walk only hides the secondary
crash and still leaves AppleDCP with an aborting register read → it never boots the mailbox.
**A kernel patch cannot fix crash A's cause.** If any kernel patch is applied for diagnostics,
log it as `vmaddr / file-offset / before→after` and update
`research/0_binary_patch_comparison.md` per CLAUDE.md.

---

## 4. Next stage — after AFK is up, decode the guest surface (Task 4)

Once the SEA is gone and `[dcp] AFK INIT` fires, `dcp_ep_handler` in `hw/arm/apple_dcp.c`
already drives the ring handshake to "transport up" (verified by reading the file):

`RBEP_INIT → INIT_ACK + GETBUF` (`apple_dcp.c:105`) → guest `RBEP_GETBUF_ACK` gives
`s->bfr_dva` (`:117`, `GETBUF_ACK_DVA_MASK = GENMASK(47,0)`) → we send `INIT_TX` / `INIT_RX`
(first / second half of the 0x1000 buffer, `:123`/`:128`) → `START` (`:132`) → guest
`START_ACK` sets `s->started` (`:137`).

**The gap:** `RBEP_RECV` (`case` at `apple_dcp.c:143`) is **only `printf`'d** — the ring is
never read. That is where IOMFB/EPIC RPC arrives. To scan out the guest's real surface:

1. Add a parsed-surface struct to `AppleDCPState`, e.g.
   `struct { uint64_t iova; uint32_t w, h, stride, fmt; } surf; bool surface_live;`
   (fields sit next to the existing `bfr_dva` / `fb_base` / `surface_live` at `:59-76`).
2. In `RBEP_RECV`: `address_space_read(&address_space_memory, s->bfr_dva, …)` the TX ring
   (first half of the buffer at `bfr_dva`; RX = second half at `+0x800`), parse the AFK ring
   header (read/write pointers), and walk the EPIC sub-messages. The IOMFB call carrying the
   surface is **`swap_submit` / `swap_start`** (`IOMobileFramebuffer::swap_submit_dcp`): it
   holds the IOSurface descriptor — DMA `iova` base, `stride` (bytes/row), `width`, `height`,
   pixel format. Mirror roles from Asahi `drivers/gpu/drm/apple/afk.c` + `dcp/` (we are the
   coprocessor; their AP-side *send* == our *receive*). Fill `surf`, set `surface_live`.
3. In `dcp_paint` (`:246`): when `surface_live`, replace the synthetic renderer with
   `address_space_read(surf.iova, stride*h)` and blit/format-convert into `fb_base` — the
   DarwinFB console already scans out `fb_base` (`darwin.c` `init_framebuffer` /
   `darwin_fb_update`; `apple_dcp.c` already writes `fb_base` via `address_space_write` at
   `:336`).
4. Send the matching AFK **completion/ack** back on the RX ring so the guest's swap completes
   and queues the next frame (otherwise IOMFB stalls after one surface).

`surf.iova` is a **DART/IOMMU** address. Since we deliberately do **not** stub `dart-dcp` in §3,
treat `iova` as guest-physical/identity first and verify the pixels look right; add
`dart-dcp` translation only if the surface is remapped (and if so, model that DART properly,
not as RAZ/WI).

---

## 5. Ordered "try this" plan

1. **Reveal the FAR.** Boot the existing repro (`DARWIN_RTKIT=1 DARWIN_FB=1`,
   `dtree_nr2_pram`) with `-d unimp,guest_errors`; read off the unclaimed DCP MMIO address at
   the crash. *(Optional: the §2.2 diagnostic `sleh` patch to make `far` print in-panic.)*
   *Observable:* the abort address = an `arm-io/dcp*` / `disp0` register offset.
2. **Selective stub.** Add `DARWIN_DISP=<node>` for exactly that node (`dcp0-expert` first),
   **no `dart-*`**. *Observable:* SEA gone; `[rtkit:dcp] CPU_CONTROL RUN` → `HELLO` → `EPMAP`
   → `STARTEP 0x24` → **`[dcp] AFK INIT`**.
3. **If a stubbed reg is polled:** promote that one node to a tiny `memory_region_init_io`
   returning the constant AppleDCP expects (find the offset in the `-d unimp` trace).
4. **Surface decode.** Implement §4 in `apple_dcp.c` (read TX ring at `bfr_dva` on `RBEP_RECV`,
   parse `swap_submit` for `{iova,stride,w,h,fmt}`, blit guest surface → `fb_base`, ack on RX).
   *Observable:* the console shows the guest's real IOMFB surface; swaps keep flowing.

---

## 6. Scripts (`./scripts/`, use `/Users/maliosdark/vphone-cli/.venv`)

- `kc.py` — segment map + static/runtime disasm + v2f/f2v/xref. `kc.py dis 0xfffffff00ac9376c`.
- `fileset.py` — static vmaddr → owning `LC_FILESET_ENTRY` kext + segment.
- `rawbl.py` — **definitive** raw `BL`/`B` xref (no capstone desync). `rawbl.py 0xfffffff00ac9376c`.
- `chained.py` — `LC_DYLD_CHAINED_FIXUPS` (format 8, `DYLD_CHAINED_PTR_64_KERNEL_CACHE`)
  resolver; proves no data pointer targets the dispatcher.
- `addr_taken.py` — adrp+add materialization + DATA-pointer scan for an address.
- `disc_fast.py` — fast raw scan for a PAC-discriminator immediate; classify SIGN/CALL/AUTH.
- `sign_ctx.py` — context around a sign site.
- `hwerr_table.py` — dump the overrun table `0xfffffff007de2338`, resolve entries, mark where
  the 7 valid `hwerr_type_*` rows end and the string pool begins.

### Cited sites (vmaddr / file offset / fileset)

| what                                            | static vmaddr        | file offset | fileset / segment                 |
| ----------------------------------------------- | -------------------- | ----------- | --------------------------------- |
| sleh sync-exception handler (fn start)          | `0xfffffff00ac6548c` | `0x3c6148c` | com.apple.kernel `__TEXT_EXEC`    |
| ↳ external-abort FSC filter (`tst`)             | `0xfffffff00ac65ac8` | `0x3c61ac8` | com.apple.kernel `__TEXT_EXEC`    |
| ↳ external-abort guard branch (patch site, diag)| `0xfffffff00ac65ad0` | `0x3c61ad0` | com.apple.kernel `__TEXT_EXEC`    |
| ↳ `BL` to hwerr decoder (crash A caller)        | `0xfffffff00ac65ae4` | `0x3c61ae4` | com.apple.kernel `__TEXT_EXEC`    |
| hwerr decoder / syndrome reader (fn start)      | `0xfffffff00ac92f08` | `0x3c8ef08` | com.apple.kernel `__TEXT_EXEC`    |
| ↳ table-load + `BL` dispatcher (DPC group)      | `0xfffffff00ac9304c` | `0x3c8f04c` | com.apple.kernel `__TEXT_EXEC`    |
| generic table-walk dispatcher (fn start)        | `0xfffffff00ac9376c` | `0x3c8f76c` | com.apple.kernel `__TEXT_EXEC`    |
| ↳ faulting `blraa x8,#0xba5`                    | `0xfffffff00ac937c4` | `0x3c8f7c4` | com.apple.kernel `__TEXT_EXEC`    |
| hwerr decoder table (DPC group, `x2`)           | `0xfffffff007de2338` | see `v2f`   | com.apple.kernel `__DATA_CONST`   |
| ↳ 7 valid `hwerr_type_*` entries                | `+0x000..+0x090`     | —           | (stride 0x18, cb@+8 disc 0xba5)   |
| ↳ string pool begins (overrun)                  | `+0x0a8`             | —           | com.apple.kernel `__DATA_CONST`   |
| panic `pc` = string `" (bad cmd)"`              | `0xfffffff00706e459` | see `v2f`   | com.apple.kernel `__TEXT`         |
| `"sleh.c"` / `"Panic lockdown…platform error"`  | `0xfffffff007067a17` / `…a3e` | —  | com.apple.kernel `__TEXT`         |
| `"DPC"` group label                             | `0xfffffff00706d2b0` | —           | com.apple.kernel `__TEXT`         |

QEMU side (read-only reference — do not edit here):
`hw/arm/apple_dcp.c` (`dcp_ep_handler` `RBEP_*`, `bfr_dva` `:63/:117`, `RBEP_RECV` `:143`
log-only, `dcp_paint` `:246`, `fb_base` write `:336`), `hw/arm/darwin.c`
(`init_display_stub` ≈`:1189` `DARWIN_DISP` substring RAZ/WI stubs; `init_darts` `:1164`;
`init_rtkit_dcp` `:1014`; `init_framebuffer`), `hw/arm/apple_rtkit.c`
(`rtkit_write`→`ASC_CPU_CONTROL_RUN`→`apple_rtkit_boot`). `dt_fixup.py` `DCP_*` (≈`:257-355`)
addresses the earlier secure-route/firmware stage, not crash A.
