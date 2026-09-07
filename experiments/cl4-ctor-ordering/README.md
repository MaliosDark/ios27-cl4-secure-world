# CL4 constructor ordering - analysis and fix design

Authorized security research (user's own machine). Analysis only. No qemu build,
no boot, no edits to the live `/Users/maliosdark/darwin-vm/qemu-sptm` tree.

Target: `firmware/exclave_comp/txtk` (CL4 secure kernel `__TEXT`).
`vmaddr` base `0xc0000000`; file offset `= vmaddr - 0xc0000000`.
`phys = rx_phys + (vmaddr - 0xc0000000)`, `rx_phys = 0x10006884000`.
`__DATA` is loaded contiguously right after `__TEXT` (RESUME UPDATE 5), so a
`__DATA` vmaddr `V` is at `phys = rx_phys + (V - 0xc0000000)` too.

Scripts (run with `/Users/maliosdark/vphone-cli/.venv/bin/python`):
- `disas.py <vmaddr> [n]` - disassemble n insns, prints fo + phys.
- `scan2.py {msr|mrs|svc|eret|hvc}` - word-by-word sysreg/exception scan.
- `xref.py <vmaddr>` - BL/B and ADRP+ADD xrefs to a target.
- `reach.py <start> <t..>` - bounded call-graph reachability (bl + tail-b).
- `find_vectors.py` - vector-table heuristic (result: none; see below).

--------------------------------------------------------------------------------
## TL;DR - answer to the KEY QUESTION

**Yes, entry is the wrong place to run the ctors - but the deeper answer is that
a ctor-runner trampoline should not exist at all.** CL4 runs its own
`__mod_init_func` pass, and it does so *after* its own `domain-setup` has
installed the real per-thread environment. Two independent facts settle it:

1. **Ordering (proven):** CL4's entrypoint calls `domain-setup` (`0xc00a6ea4`),
   which installs the *real* `TPIDR_EL0` (a per-thread context) and registers the
   *base per-thread services*. CL4 then reaches its *own* `__mod_init_func`
   runner (`0xc015c3b4 → 0xc015c03c`, iterating `[0xc0698fc0, 0xc0699018)`), which
   runs the 11 ctors with that environment live. The current trampoline runs the
   ctors at **entry**, before `domain-setup` - which is exactly why `domain-setup`
   "never executes (0 hits)" (RESUME UPDATE 16) and why every ctor prerequisite
   (`TPIDR_EL0`, `TPIDRRO_EL0`, the `(2,x)` registry) is missing. That is the
   whack-a-mole. The fake `TPIDR`/`TPIDRRO`/registry seeding in the loader is
   reconstructing, by hand and in the wrong order, what CL4 installs for itself a
   few calls later.

2. **The `svc` is not a CL4 syscall - it is a call to the SPTM monitor (proven).**
   CL4 `__TEXT` contains **zero** `msr vbar_el{1,2,3}`, **zero** `eret/eretaa/eretab`,
   and **zero** `mrs esr_el1 / far_el1 / elr_el1 / spsr_el1`. A kernel that
   handled its own exceptions would need all three. CL4 has none - **CL4 has no
   exception vectors and no exception-handling code at all.** Its 440 `svc`
   instructions (immediates `#0..#5`) are **guarded-monitor calls to SPTM** (the
   guarded-EL2 monitor), the exclave equivalent of a hypercall. So "install
   VBAR_EL1 and run ctors after it" is the wrong frame: there is no CL4 VBAR to
   install. The `svc` must be *delivered to SPTM*. In this qemu fork a
   guarded-EL1 `svc` vectors to `env->vbar_gl[1]` (`helper.c:9409`), which is
   **never written anywhere in the fork** (`cpu.h:829` declare + one read), so it
   goes to `0` and cascades - the fault at `0xc009a9c0`.

Consequence: **fixing ordering removes the `TPIDR`/registry faults at their root,
but is not sufficient by itself** - CL4's ctors emit log records via an SPTM call
(`svc`), so the guarded-`svc`→SPTM path must also be made to work (or be
emulated). Both are needed; they are independent.

--------------------------------------------------------------------------------
## 1. Entrypoint and early-init map

Entry `0xc00994f0` (fo `0x994f0`, phys `0x1000691d4f0`; `LC_UNIXTHREAD`).
Cold boot arrives with `SP == 0` (`cmp sp,#0 ; b.ne` at `0xc00994f8`), taking the
`x22 = 1` primary path. It:

- builds the `{tag,value}` boot-info array at `0xc06ff3f0` (tags `0x15, 0x1a, 2, 3`),
- sets a temporary stack (`sp = 0xc06d8000 + [0xc068c000]`),
- calls, in order (x22==1 path):

| call site (vmaddr / phys)      | target (vmaddr / phys)          | role |
|--------------------------------|----------------------------------|------|
| `0xc0099704` / `0x1000691d704` | `0xc00a7b3c` / `0x1000692bb3c`   | early stack/thread bring-up (returns new SP) |
| `0xc0099734` / `0x1000691d734` | **`0xc00a6ea4` / `0x1000692aea4`** | **domain-setup** (installs TPIDR + base registry) |
| `0xc0099740` / `0x1000691d740` | `0xc0098004` / `0x1000691c004`   | main init (phased, callback-driven) |

(The `x22 != 1` secondary path calls the same two functions at `0xc00996bc` and
`0xc009968c`; its post-domain-setup return is `0xc00996c0`.)

### domain-setup `0xc00a6ea4` installs the environment

Disassembly of `0xc00a6ea4`:
- `0xc00a6edc  mrs x8, tpidr_el0 ; cbz x8, 0xc00a700c` - first-run path when
  `TPIDR_EL0 == 0`. That path allocates a per-thread context (`x24`), fills it,
  and at:
- **`0xc00a7114  bl 0xc00aa724`** - calls the TPIDR setter
  `set_tpidr_el0(x0){ msr tpidr_el0, x0 ; ret }` (`0xc00aa724`, phys
  `0x1000692e724`; the **only** `msr tpidr_el0` in the whole image), i.e. installs
  the **real** `TPIDR_EL0`. Loops back to re-check (now non-zero).
- **`0xc00a7178  bl 0xc00982e0`** - calls the **base per-thread registrar**
  `0xc00982e0` with `x0 = [x23+0x10]` (`x23` = boot-info array). This populates
  the base `(key1,key2)` per-thread services that the `(2,x)` lazy factories read.

**Environment-ready PC = the return of `domain-setup`:** `0xc0099738`
(phys `0x1000691d738`) on the cold-boot path (`0xc00996c0` on the secondary
path). After this PC, `TPIDR_EL0` = CL4's real per-thread context and the base
registry is live.

`TPIDRRO_EL0` is the read-only per-thread word CL4's own code reads (e.g. the log
path `0xc009a890` does `mrs x23, tpidrro_el0 ; ldrb w8,[x23,#9]`). It is set by
the same guarded bring-up (hardware/SPTM provides it at genter); CL4 never writes
it via a caught instruction - consistent with it being monitor-provided.

--------------------------------------------------------------------------------
## 2. The ctors are CL4's own, and run after domain-setup

`__DATA,__mod_init_func` = `0xc0698fc0 .. 0xc0699018` (fo `0x698fc0`, 11 × 8-byte
pointers, `S_MOD_INIT_FUNC_POINTERS`). Contrary to RESUME UPDATE 11, **CL4 does
contain a runner for it.**

- **Iterator** `0xc015c298` - calls each pointer in a `[start,end)` init array.
- **Runner** `0xc015c03c` - takes a flag in `w0`; when set, runs the init arrays:
  `__DATA_CONST,__mod_init_func` (empty), then **`__mod_init_func`
  `[0xc0698fc0, 0xc0699018)`** (the 11 ctors), then `0xc0669b30`-region arrays.
  (`0xc015c084`/`0xc015c08c` materialize exactly `0xc0698fc0`/`0xc0699018`.)
- **Wrapper** `0xc015c3b4` - `w0=1 ; bl 0xc00982b0 ; ... ; b 0xc015c03c` (the C++
  "run static constructors" entry).
- **Called from** `0xc0097fb4` (`bl 0xc015c3b4`) inside function **`0xc0097e3c`**,
  which is guarded by a "ctors-done" byte at `0xc06fecd8` (`tbnz` at entry;
  `strb #1` at `0xc0097fc4`) - i.e. CL4's own idempotent init step, not an
  external loader.

Placement in the boot flow (`reach.py`): from `0xc0098004` (main init, called
*after* domain-setup) the `(2,5)` getter `0xc0098ce0` is reachable in 13 hops via
the phased-callback dispatcher `0xc00a675c`. `0xc0097e3c`/`0xc015c3b4` are invoked
through **PAC-signed indirect callbacks** (`blraa`) that a static `bl` walker
cannot follow (e.g. `0xc0098004` signs `0xc0098214` and hands it to `0xc00a675c`);
they are earlier phases of the same callback-driven init. The design is a phased
init: **domain-setup → (callbacks incl. the `__mod_init_func` pass) → subsystem
consumers**. The `(2,5)` consumer is a lazy getter:

```
0xc0098ce0  get_singleton_2_5():
    x0 = 0xc06fece0 ; w1=2 ; w2=5 ; bl 0xc00a0e58 (factory) ; x0=[x0+0x2a0] ; ret
```

It faults only when the `(2,5)` registry is still empty - i.e. only when the ctor
pass has not run (our entry-time trampoline) or has not completed (the `svc`
fault). In correct order it is seeded first.

--------------------------------------------------------------------------------
## 3. What the ctor `svc` at `0xc009a9c0` is

The faulting `svc` is `0xc009a9bc  svc #0` (the RESUME's `0xc009a9c0` is the
*return* address). It sits inside a **log/trace primitive** `0xc009a890`
(phys `0x1000691e890`):

```
0xc009a8e0  bl   0xc0093654            ; x22 = log channel / endpoint handle
0xc009a8e4  mrs  x23, tpidrro_el0      ; read per-thread RO id
0xc009a8e8  ldrb w8,[x23,#9] ...       ; pull thread-id bytes for the record
   ... marshal bytes of x8/x2 into the record buffer [x23] ...
0xc009a9b4  mov  x0, x22 ; mov x1, #0
0xc009a9bc  svc  #0                    ; -> SPTM: emit the log/trace record
0xc009a9c0  ... ; cmp x0,#1 ; b.eq (retry)   ; x0 = SPTM return status
```

`svc #0` with `x0 = channel`, `x1 = 0`, returning a status in `x0`. This is a
**guarded-monitor call to SPTM** to emit a secure log record. The immediate
distribution across all 440 `svc` (`scan`): `#0`×304, `#1`×25, `#2`×12, `#3`×44,
`#4`×44, `#5`×8 - the immediate selects the SPTM **call class**; the operation
within a class is register-selected (`x0`). (Also 10 `hvc`, 3 `smc` - EL2/EL3
monitor calls.)

Because CL4 has **no** vectors, no `eret`, and no `esr/elr/spsr` access, none of
these can be serviced *by CL4*. They are serviced by **SPTM**, which is loaded and
running as the guarded monitor. "Running the ctors after VBAR install" cannot help
 - there is no CL4 VBAR. What is missing is the guarded-EL1→SPTM delivery.

--------------------------------------------------------------------------------
## 4. Fix design

### 4.1 Ordering fix (root cause) - recommended, path (a)

Stop forcing the ctors at CL4 entry. Let CL4 run its own early-init so the
environment is built by CL4 in the right order, then the ctors run through CL4's
own runner.

Concretely, in `target/arm/tcg/helper-a64.c` `HELPER(exception_return)`:

- **Remove** the entry-time ctor-runner divert (the
  `g_cl4_tramp_pc && !g_cl4_ctors_done && new_pc == g_cl4_entry_pc` block,
  lines ~782-795), and **remove** the fake `TPIDR`/`TPIDRRO` writes it does
  (`env->cp15.tpidr_el[0] = g_cl4_tpidr`, `...tpidrro_el[0] = g_cl4_tpidrro`).
  Those invert the order and mask CL4's real environment.
- In `hw/arm/xnuboot_sptm.c`, stop building the trampoline + fake per-thread
  context + pre-seeded `(2,5)` node (the whole `if (!getenv("CL4_NO_CTORS"))`
  block, ~lines 476-534). Keep the CL4 scratch page only if still used for the
  x1 probe.
- Keep the x1 injection (`g_cl4_x1_inject` at the entry ERET) **only** if the
  handoff still delivers `x1 == 0` / tag3-null; drop it once the handoff carries a
  real tag3. It is orthogonal to ordering.

CL4 then executes `entry → 0xc00a7b3c → domain-setup(0xc00a6ea4) →
main-init(0xc0098004) → …`, installs its real `TPIDR_EL0` + base registry, and
reaches its own `__mod_init_func` pass with the environment live.

**If a divert-based runner is still wanted** (e.g. because our synthesized handoff
does not drive CL4's indirect-callback init all the way to the `__mod_init_func`
phase), gate it on the **environment-ready PC, not entry**, and use CL4's *real*
`TPIDR`:

- Gate PC = `0x1000691d738` (`vmaddr 0xc0099738`, domain-setup return, cold path)
 - or `0x1000691d6c0` (`0xc00996c0`) on the secondary path.
- At the gate, `env->cp15.tpidr_el[0]` already holds CL4's real per-thread context
  (domain-setup set it) - **do not overwrite it**. Save `x0..x30/SP/PC`, point PC
  at a trampoline that calls the runner (or better, call CL4's own wrapper
  `0xc015c3b4` at phys `0x100069e03b4` with `w0=1`), then restore and resume at the
  gate PC. No fake registry seeding is needed because the base registry is live.
- Because the gate PC is a normal instruction (reached by `blr` return, not an
  ERET), it cannot be caught in `HELPER(exception_return)`. Add a cheap one-shot
  PC check in the guarded-execution translate/exec path, or hook the **real**
  `msr tpidr_el0` write (`0xc00aa724`) - the CP write helper for `TPIDR_EL0` - 
  as the "environment coming up" signal (domain-setup's registrar runs a few
  instructions later, so resume-and-recheck, or defer the divert to the first
  guarded instruction fetch at/after `0xc0099738`).

Recommendation: prefer "no trampoline at all". The divert-at-gate variant is the
fallback if CL4's own callback init proves not to fire in the synthesized boot.

### 4.2 Guarded-`svc` → SPTM delivery (independent, still required)

Even with perfect ordering, a ctor's log call `svc #0` (`0xc009a890`) will trap.
In this fork a guarded-EL1 synchronous exception is delivered to
`env->vbar_gl[new_el=1]`, which is never populated. On real hardware GXF delivers
guarded-EL1 exceptions/monitor-calls to the guarded monitor (SPTM). Two options:

- **(A) Faithful - route guarded-EL1 synchronous exceptions to SPTM.** Make an
  `svc` (and the FP/alignment sync exceptions the fork currently *suppresses* for
  guarded state, `fp_exception_el`/`ptw`/`hflags`) escalate to SPTM's monitor
  entry instead of staying at EL1 with `vbar_gl[1]=0`. SPTM already runs as the
  guarded monitor; it entered CL4 via `genter` (which uses `env->gxf_entry_el[]`,
  `helper.c:9561`). Deliver the guarded sync exception the same way genter does
  (transition to GL2, `addr = gxf_entry_el[2]`, bank `spsr_gl/elr_gl/esr_gl`), so
  the real SPTM `svc`/exception handler services the call and returns to GL1. This
  is the correct long-term fix and needs no knowledge of the SPTM call ABI.
 - Minimum viable version: at least make the write path to `vbar_gl[]` exist and
    honor it (today it is write-dead), and add the GL1→GL2 sync-exception path.

- **(B) Research shortcut - trap-and-emulate the log `svc` in qemu.** For
  `svc #imm` taken in guarded state (`env->currentg`) with `vbar_gl[1]==0`, decode
  the class (immediate) and, for the log/trace call (`#0`, `x1==0`), consume the
  record buffer (optionally print it to `-d int`), set `x0` = success status
  (`!= 1` so the retry loop at `0xc009a9c0` exits), and return to `ELR` (the insn
  after the `svc`). This unblocks the ctor pass without SPTM, but `svc #0` is the
  general SPTM-call gate (register-selected), so other classes will need their own
  emulation - brittle; use only to see the next stage, prefer (A).

### 4.3 Note on the qemu gap

`env->vbar_gl[4]` is declared (`cpu.h:829`) and read once (`helper.c:9409`) but is
**never written** in the fork, and there is no GL1→GL2 sync-exception escalation.
So guarded-EL1 exceptions can only ever vector to 0 today. Whichever of (A)/(B)
is chosen, this is the concrete missing mechanism.

--------------------------------------------------------------------------------
## 5. Reveal / validation procedure (do this on the next boot; not run here)

1. Apply 4.1 (remove entry trampoline + fake TPIDR/registry). Boot with
   `-d int -D /tmp/int.log`. Expect CL4 to now execute `domain-setup`
   (`0x1000692aea4`) - confirm with a `-dfilter 0x1000692aea4..0x1000692aeb0`
   exec trace showing ≥1 hit (previously 0). Confirm the real `msr tpidr_el0` at
   `0x1000692e724` executes (guarded TPIDR write).
2. The first fault should now be the guarded `svc` at `0x1000691e9bc` (log call),
   reached *through CL4's own path*, with `env->cp15.tpidr_el[0] != 0`. This
   verifies the ordering fix: TPIDR/registry are live; the only blocker left is
   `svc`→SPTM.
3. Apply 4.2. With (A), confirm the guarded `svc` transitions to SPTM
   (`gxf_entry_el[2]`) and returns; with (B), confirm `x0` return + the retry loop
   at `0x1000691e9c0` exits. Then chase the next frontier (the `(2,5)` getter
   `0x1000691cce0` should now be *seeded* by the completed ctor pass, not null).
4. If CL4's own `__mod_init_func` pass does not fire (no hits at the runner
   `0x100069e003c` / wrapper `0x100069e03b4`), switch to the 4.1 fallback: divert
   to `0x100069e03b4` (`w0=1`) gated at `0x1000691d738` with the real TPIDR.

--------------------------------------------------------------------------------
## Appendix - address table (vmaddr / file-offset / phys, rx=0x10006884000)

| symbol / role                         | vmaddr       | fo        | phys           |
|---------------------------------------|--------------|-----------|----------------|
| entrypoint                            | `0xc00994f0` | `0x994f0` | `0x1000691d4f0`|
| early bring-up (blr#1)                | `0xc00a7b3c` | `0xa7b3c` | `0x1000692bb3c`|
| **domain-setup**                      | `0xc00a6ea4` | `0xa6ea4` | `0x1000692aea4`|
| domain-setup blr (x22==1)             | `0xc0099734` | `0x99734` | `0x1000691d734`|
| **env-ready PC (domain-setup return)**| `0xc0099738` | `0x99738` | `0x1000691d738`|
| env-ready PC (secondary path)         | `0xc00996c0` | `0x996c0` | `0x1000691d6c0`|
| main init                             | `0xc0098004` | `0x98004` | `0x1000691c004`|
| TPIDR setter (`msr tpidr_el0`)        | `0xc00aa724` | `0xaa724` | `0x1000692e724`|
| TPIDR setter call (in domain-setup)   | `0xc00a7114` | `0xa7114` | `0x1000692b114`|
| base registrar `0xc00982e0` call      | `0xc00a7178` | `0xa7178` | `0x1000692b178`|
| base registrar                        | `0xc00982e0` | `0x982e0` | `0x1000691c2e0`|
| C++ ctor wrapper                      | `0xc015c3b4` | `0x15c3b4`| `0x100069e03b4`|
| ctor runner (flag in w0)              | `0xc015c03c` | `0x15c03c`| `0x100069e003c`|
| init-array iterator                   | `0xc015c298` | `0x15c298`| `0x100069e0298`|
| ctor pass call site (`bl` wrapper)    | `0xc0097fb4` | `0x97fb4` | `0x1000691bfb4`|
| ctor-caller fn (done-flag guarded)    | `0xc0097e3c` | `0x97e3c` | `0x1000691be3c`|
| ctors-done flag byte                  | `0xc06fecd8` | (`__DATA`)| `0x10006f82cd8`|
| `__mod_init_func` start (11 ptrs)     | `0xc0698fc0` | `0x698fc0`| `0x10006f1cfc0`|
| `__mod_init_func` end                 | `0xc0699018` | `0x699018`| `0x10006f1d018`|
| log/trace primitive (does the `svc`)  | `0xc009a890` | `0x9a890` | `0x1000691e890`|
| the ctor `svc #0`                     | `0xc009a9bc` | `0x9a9bc` | `0x1000691e9bc`|
| `(2,5)` lazy getter                   | `0xc0098ce0` | `0x98ce0` | `0x1000691cce0`|

Facts confirmed by raw-encoding scan of the whole `txtk`:
`msr vbar_el{1,2,3}` = 0, `mrs vbar_el1` = 0, `eret/eretaa/eretab` = 0,
`mrs esr_el1/far_el1/elr_el1/spsr_el1` = 0, `msr tpidr_el0` = 1 (only `0xc00aa724`),
`svc` = 440 (imm `#0..#5`), `hvc` = 10, `smc` = 3.
