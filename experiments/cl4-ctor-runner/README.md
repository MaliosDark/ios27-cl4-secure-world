# CL4 `__mod_init_func` constructor runner

Design + code for running Apple CL4 (exclave secure kernel) static constructors
under the QEMU `-cl4` boot, so CL4's internal registries get populated before its
main init consults them.

> **Scope of this deliverable:** design + code only. Nothing here builds QEMU or
> boots. The integration steps below are written as a **patch to apply later** to
> `/Users/maliosdark/darwin-vm/qemu-sptm` — that live tree must NOT be edited now
> (a concurrent task owns it). Apply the diffs described in
> [Integration](#integration-apply-later) when the tree is free.

All addresses are cited as `vmaddr` (CL4 image base `0xc0000000`) and as file
offsets into the extracted components:

| component | file | maps to | offset rule |
|---|---|---|---|
| `__TEXT` | `firmware/exclave_comp/txtk` | vmaddr `0xc0000000` | `fileoff = vmaddr - 0xc0000000` |
| `__DATA` | `firmware/exclave_comp/tadk` | vmaddr `0xc068c000` | `fileoff = vmaddr - 0xc068c000` |
| assembled | `firmware/cl4_full` | loaded with `-cl4` | `__TEXT | __DATA | __LINKEDIT` contiguous |

Physical layout at boot (from `RESUME-secure-world.md` UPDATE 5, contiguous load):

```
rx_phys      = 0x10006884000          (CL4 __TEXT base; vmaddr 0xc0000000)
phys(vmaddr) = rx_phys + (vmaddr - 0xc0000000)
CL4 entry    = 0x1000691d4f0          (= rx_phys + 0x994f0 ; vmaddr 0xc00994f0)
__DATA base  = 0x10006f10000          (= rx_phys + 0x68c000 ; vmaddr 0xc068c000)
```

---

## 1. What the constructors are and how they must be called

`__DATA,__mod_init_func` @ **vmaddr `0xc0698fc0`** (fileoff `tadk`+`0xcfc0`),
size `0x58` = **11 × 8-byte pointers**, section flags `0x09`
(`S_MOD_INIT_FUNC_POINTERS`). Per the Mach-O ABI these are C++/runtime static
constructors that the **image loader** runs *before* it calls the image's
entrypoint. Our synthesized boot ERETs straight into CL4's entry and never runs
them, so every registry the constructors would populate is empty — this is the
single root cause behind the cascade of null-deref faults in UPDATES 4–8.

The 11 constructor vmaddrs (decoded from the chained-fixup slots, which the
loader's `apply_cl4_fixups()` already rebases to physical):

```
idx  vmaddr       phys (= rx_phys+off)   notes
 0   0xc0001800   0x10006885800          mov w0,#0 ; b 0xc00a6cd4  (writes bool @0xc068e9a0 = 0)
 1   0xc00795d4   0x100068fd5d4          one-shot guard (ldrb flag @0xc06fe6d0; tbz; ret)
 2   0xc00a2ad4   0x10006926ad4          REGISTRAR: seeds descriptor table 0xc068e840 (see below)
 3   0xc00aa814   0x1000692e814          fills a __DATA vtable array @0xc06d0190 (paciza fn ptr 0xc00a1468)
 4   0xc01552bc   0x100069d92bc          paciza-signs pointers; 1 call (0xc0155344)
 5   0xc03c9868   0x10006c4d868          b 0xc039c864 (tail); tiny
 6   0xc04020e4   0x10006c860e4          3 calls; builds a subsystem table
 7   0xc0402e98   0x10006c86e98          3 calls (0xc015b440/3dc/390 — string/registry helpers)
 8   0xc0437ef0   0x10006cbbef0          1 call (0xc03899cc)
 9   0xc0439524   0x10006cbd524          4 calls; largest (109 ins) — registers several factories
10   0xc043a8a4   0x10006cbe8a4          4 calls (0xc039c3f0 ×2, 0xc0438850 ×2)
```

### Calling convention (verified by static analysis of all 11)

* **No arguments.** Every constructor is an ordinary AAPCS function that takes no
  input in `x0..x7`. `ctor[0]` and `ctor[2]` were disassembled in full; neither
  reads incoming argument registers. The rest follow the same C++ static-ctor
  shape. They can be called **in array order with no arguments**.
* **AAPCS callee-saved discipline.** Each constructor that uses `x19..x28`
  saves/restores them (`stp x20,x19,[sp,#-0x20]!` … `ldp … ; retab`). Therefore
  `x19..x24` **survive across every constructor call** — the trampoline keeps all
  its loop state there.
* **They need a stack.** Constructors `stp`/`ldp` to `[sp,...]`. At CL4 entry
  `SP == 0` (SPTM ERETs with SP=0; the entrypoint sets SP up *itself* only after
  the `cmp sp,#0` test). So the runner must install a scratch stack before the
  loop and restore `SP=0` before handing control to the real entry.
* **PAC.** Constructors sign/authenticate their own return with key B
  (`pacibsp` … `retab`), self-balanced against their own SP frame. This already
  round-trips in the current CL4 boot (CL4 executes `retab` in its normal init),
  so a plain `blr`/`br`-based runner that never signs *its own* `x30` is
  PAC-agnostic and safe.

### The two registries — and why running the ctors at entry is correct

CL4 has **two** distinct registry mechanisms:

1. **Static `__DATA` descriptor tables**, e.g. the domain-descriptor table at
   **`0xc068e840`** (stride `0x50`, 4 slots up to `0xc068e980`). `ctor[2]`
   (`0xc00a2ad4`) is the registrar that fills it: it loops indices 1..3 and calls
   `register()` @ **`0xc00a2b28`**, which `memcpy`s a `0x50`-byte descriptor into
   `0xc068e840 + idx*0x50` (via `0xc015af50`). **No TPIDR involved.**

2. **Per-thread linked-list registry** read by the factory @ **`0xc00a1e70`**:
   `mrs x8,tpidr_el0 ; ldr x8,[x8,#0x10] ; ldr x9,[x8]` (list head), walks a
   singly-linked list matching `(key1,key2)=([node+8],[node+0x10])`, returns
   `[node+0x18]`. This is a *different* registry, populated by CL4's own
   domain-setup path.

**Key correction to UPDATE 11:** UPDATE 11 asserted "no `msr tpidr_el0` anywhere
in CL4 `__TEXT`" and concluded TPIDR is set by SPTM/GXF, so the ctors would need
a pre-built per-thread context. A byte-accurate scan (linear capstone disasm
desyncs — must scan the `0xd51bd040|Rt` encoding directly) shows **exactly one**
`msr tpidr_el0, x0` at **`0xc00aa724`** (a 2-instruction setter `msr; ret`).
**CL4 installs its own TPIDR_EL0** during domain setup — the per-thread context
is *not* required to pre-exist, and it is *not* something the constructor pass has
to build.

Consequently the constructors are **TPIDR-independent table initializers**: none
of the 11 reads `tpidr_el0` (all 50 `mrs tpidr_el0` sites lie outside the 11
constructor bodies), and their direct callees that matter (`ctor[2]`→`0xc00a2b28`)
write static `__DATA` tables. `ctor[2]` populating `0xc068e840` is exactly the
domain-descriptor table that CL4's domain setup reads — the "garbage domain id
`0x50`" fault (UPDATE 4/5) is that table being **empty because `ctor[2]` never
ran**. Running the constructors at entry seeds the static tables so CL4's own
domain setup then succeeds, installs TPIDR (`0xc00aa724`), and seeds the
per-thread registry itself.

This also matches the real hardware order: the loader runs `__mod_init_func`
**before** the entrypoint. Running them in a trampoline immediately ahead of
`0x1000691d4f0` is the faithful reproduction — *not* a hack that fights ordering.

---

## 2. TPIDR_EL0 and the per-thread context

* At the diversion point (CL4 entry) `TPIDR_EL0` holds whatever SPTM's genter
  left; the constructors **do not touch it**, so its value is irrelevant to them.
* CL4 later builds the real per-thread context and installs it with `msr
  tpidr_el0,x0` @ `0xc00aa724`. The context has: `[+0x10]` = registry list head
  (read by factory `0xc00a1e70`), `[+0x18..+0x100]` = a slot table, `[+0xf8]` =
  a busy flag (see `0xc00aa660` / `0xc00aa734`).
* **No manual per-thread-context or registry-head allocation is required.**
  The earlier plan to hand-allocate a context whose `[+0x10]` points at a NULL
  head is unnecessary: CL4 does this itself once the static descriptor tables
  (seeded by the ctors) let domain setup proceed. This removes a whole class of
  guesswork (correct context size, field layout, list-node ABI).
* If, after running the ctors, a *later* fault shows the factory still returning
  NULL, the fallback is the original probe idea — reserve a scratch cell and make
  a specific registry non-empty — but the constructor pass should make that
  unnecessary. Keep the existing `-cl4` domain-descriptor x1 probe in place
  (below) as belt-and-suspenders for the tag3 deref.

---

## 3. Mechanism — recommendation

**Recommended: option (i), a guest ARM64 trampoline**, diverted to by the
existing `exception_return` hook. Rationale:

* It runs **inside CL4's own guarded context** (MMU-off, FP-on, PAC as CL4 sees
  it), so PAC/`retab`, `adrp`-to-physical, and Normal-memory semantics are exactly
  what the constructors expect — no need to reproduce any of that QEMU-side.
* Minimal QEMU surface: **one extra global + a 3-line divert** in the hook that
  already exists (`g_cl4_entry_pc` / `g_cl4_x1_inject`). No new exit path, no
  per-instruction driver.
* Option (ii) (a QEMU-side driver that single-steps each ctor via repeated
  `exception_return`/PC surgery) is strictly harder: it must save/restore full
  guest state around each call, re-implement the return-address trap for 11
  functions with unknown internal `blr`/PAC behaviour, and re-enter guarded EL1
  cleanly each time. It buys nothing the guest trampoline doesn't already get for
  free. **Rejected.**

### The trampoline

Assembled by `gen_trampoline.py` (keystone). **104 bytes** = 72 bytes code +
a NOP pad + a 32-byte literal pool the loader fills. Position-independent; the
loader supplies all four addresses at boot (nothing hardcoded).

```asm
        ; entry: x0=handoff, x1=descriptor, SP=0, guarded EL1h, MMU off
        mov   x19, x0          ; save handoff (tag2)
        mov   x20, x1          ; save descriptor (tag3)
        ldr   x21, Larray      ; cursor = &__mod_init_func[0]  (phys)
        ldr   x22, Larray_end  ; end    = &__mod_init_func[11]
        ldr   x9,  Lstacktop   ; scratch stack top (phys, 16-aligned)
        mov   sp,  x9          ; ctors need a stack
Lloop:  cmp   x21, x22
        b.hs  Ldone
        ldr   x23, [x21], #8   ; next ctor ptr (already physical via fixups)
        blr   x23             ; call it (x19..x22 survive: AAPCS)
        b     Lloop
Ldone:  mov   x0, x19          ; restore handoff
        mov   x1, x20          ; restore descriptor
        mov   x9, xzr
        mov   sp, x9          ; CL4 entry REQUIRES SP==0
        ldr   x16, Lentry      ; real CL4 entry (phys 0x1000691d4f0)
        br    x16
        .align 3
Larray:     .quad 0   ; loader: rx_phys + 0x698fc0
Larray_end: .quad 0   ; loader: rx_phys + 0x698fc0 + 88
Lstacktop:  .quad 0   ; loader: scratch stack top
Lentry:     .quad 0   ; loader: rx_phys + 0x994f0
```

Raw bytes are in `trampoline.bin` / `trampoline.hex`; the C array + pool offsets
are printed by `gen_trampoline.py` (see `CL4_TRAMP_POOL_OFF = 0x48`,
`CL4_TRAMP_SIZE = 0x68` for the code, pool at `+0x48..+0x68`).

**Why the pool words are what they are**

* `Larray = rx_phys + 0x698fc0`: the `__mod_init_func` section, physical. Its
  eleven slots are chained-fixup pointers (`auth`, `target = raw & 0xffffffff`),
  and `apply_cl4_fixups()` already rebases each to `rx_phys + target`, i.e. the
  physical constructor address. The trampoline just loads and calls them.
* `Larray_end = Larray + 11*8` (`0x58`).
* `Lstacktop`: top (16-byte aligned) of a scratch stack in guest RAM (below).
* `Lentry = rx_phys + 0x994f0 = 0x1000691d4f0`: the real CL4 entrypoint.

### Where the trampoline + stack live

Reuse the existing **`CL4-dummypage`** scratch region, enlarged. Today it is one
`DARWIN_PAGE_SIZE` page that holds only an 8-byte domain descriptor at `+0`. Bump
its allocation to `0x8000` (32 KiB) and carve it:

```
CL4-scratch (0x8000):
  +0x0000  : 8-byte domain descriptor   (unchanged; g_cl4_x1_inject target)
  +0x0080  : trampoline code + pool      (104 bytes; g_cl4_tramp_pc target)
  +0x8000  : STACKTOP (grows down)       (Lstacktop = base + 0x8000, 16-aligned)
```

Keeping this inside the *existing* region avoids adding a new descriptor to the
region list, so SPTM's `validate_region_order` is untouched (adding regions is
what tripped it in UPDATES 1–3). Code + stack sharing one region is fine: in the
guarded domain, MMU is off and there are no page-permission checks (that is why
guarded FP/Normal/align fixes A–C were needed at all).

---

## Integration (apply later)

Two files change. **Do not edit the live tree now** — this is the patch to apply
when `/Users/maliosdark/darwin-vm/qemu-sptm` is free. Line numbers are indicative;
match on context.

### (a) `hw/arm/xnuboot_sptm.c`

1. Near the existing probe globals (`g_cl4_entry_pc`, `g_cl4_x1_inject`, ~line
   103), add:

   ```c
   uint64_t g_cl4_tramp_pc  = 0;   // phys of the ctor-runner trampoline entry
   int      g_cl4_ctors_done = 0;  // one-shot: divert to trampoline exactly once
   ```

2. Paste the `cl4_ctor_trampoline[]` byte array + `CL4_TRAMP_POOL_OFF` /
   `CL4_TRAMP_SIZE` from `gen_trampoline.py`'s output near the top of the file
   (or `#include "cl4_ctor_trampoline.inc"`).

3. In the `CL4-dummypage` block (~line 439), enlarge the allocation and install
   the trampoline. Replace the single-page bump with:

   ```c
   // CL4-scratch: domain descriptor (+0) | trampoline (+0x80) | stack (top)
   {
       hwaddr cl4_scratch = blob_head;
       const uint64_t CL4_SCRATCH_SZ = 0x8000;
       blob_head += CL4_SCRATCH_SZ;
       END_ENTRY("CL4-dummypage");            // keep the region name SPTM expects
       if (have_cl4) {
           // (unchanged) minimal domain descriptor at +0 for the x1 probe
           const char *ds = getenv("CL4_DOMAIN_ID");
           uint64_t domain_id = ds ? strtoull(ds, NULL, 0) : 0xc00000001ULL;
           address_space_write(&address_space_memory, cl4_scratch,
                               MEMTXATTRS_UNSPECIFIED, &domain_id, 8);
           g_cl4_x1_inject = cl4_scratch;
           g_cl4_entry_pc  = cl4_rx_phys + (cl4_mi.entrypoint - cl4_mi.virtlo);

           // --- ctor runner ---
           hwaddr tramp_phys = cl4_scratch + 0x80;
           // copy code
           address_space_write(&address_space_memory, tramp_phys,
                               MEMTXATTRS_UNSPECIFIED,
                               cl4_ctor_trampoline, CL4_TRAMP_SIZE);
           // fill the 4-quad literal pool
           uint64_t modinit_phys = cl4_rx_phys + 0x698fc0;      // __mod_init_func
           uint64_t pool[4] = {
               modinit_phys,                                     // Larray
               modinit_phys + 11 * 8,                            // Larray_end
               (cl4_scratch + CL4_SCRATCH_SZ) & ~0xFULL,         // Lstacktop
               g_cl4_entry_pc,                                   // Lentry
           };
           address_space_write(&address_space_memory,
                               tramp_phys + CL4_TRAMP_POOL_OFF,
                               MEMTXATTRS_UNSPECIFIED, pool, sizeof(pool));
           g_cl4_tramp_pc = tramp_phys;
           printf("[cl4] ctor-runner: tramp 0x%llX modinit 0x%llX stack 0x%llX entry 0x%llX\n",
                  (unsigned long long)tramp_phys, (unsigned long long)modinit_phys,
                  (unsigned long long)pool[2], (unsigned long long)g_cl4_entry_pc);
           fflush(stdout);
       }
   }
   ```

   Notes: `0x698fc0` is a fixed section offset from the CL4 image base — it is a
   *file/section constant* of the CL4 macho, not a per-boot magic number. If you
   prefer zero literals, resolve it at load time with
   `macho_find_sect(cl4_macho, "__DATA", "__mod_init_func")` and use its
   `addr - 0xc0000000`. Either is acceptable; the section offset is stable for
   this CL4 build.

### (b) `target/arm/tcg/helper-a64.c`

Extend the existing probe block in `HELPER(exception_return)` (~line 766). Keep
the x1 injection; add the one-shot PC divert **after** it:

```c
extern uint64_t g_cl4_tramp_pc;   // add near the existing externs (~line 22)
extern int      g_cl4_ctors_done;
...
if (g_cl4_entry_pc && new_pc == g_cl4_entry_pc &&
    env->currentg && env->xregs[1] == 0) {
    env->xregs[1] = g_cl4_x1_inject;                 // (unchanged) tag3 descriptor
    qemu_log_mask(CPU_LOG_INT,
                  "[cl4] probe: injected x1=0x%" PRIx64 " at CL4 entry\n",
                  env->xregs[1]);
}
// Divert the FIRST guarded return into CL4's entry to the ctor-runner trampoline,
// which calls the 11 __mod_init_func constructors and then branches to the real
// entry (Lentry == g_cl4_entry_pc) itself.
if (g_cl4_tramp_pc && !g_cl4_ctors_done &&
    new_pc == g_cl4_entry_pc && env->currentg) {
    g_cl4_ctors_done = 1;
    env->pc = g_cl4_tramp_pc;                         // run ctors first
    qemu_log_mask(CPU_LOG_INT,
                  "[cl4] ctor-runner: divert entry -> trampoline 0x%" PRIx64 "\n",
                  g_cl4_tramp_pc);
}
```

`env->pc = new_pc;` runs *above* this block, so overriding `env->pc` here is the
last write and wins. The x1 injection must precede the divert so the descriptor
is in place; the trampoline saves it (`x20`) and restores it before entering CL4.

---

## How to test later (no boot performed here)

1. Rebuild QEMU with the patch (`rebuild-qemu.sh`).
2. Boot exactly as UPDATE 3's command line, with `-cl4 firmware/cl4_full` and
   `-d int -D /tmp/int.log`.
3. Expect in stdout: `[cl4] ctor-runner: tramp 0x... entry 0x1000691d4f0`, and in
   the int log: `divert entry -> trampoline`, then execution flowing through the
   11 constructors (trace with
   `-d exec,nochain -dfilter <tramp>..<tramp+0x68>` and the ctor phys ranges).
4. Success signal: the domain-descriptor lookup no longer sees `0x50`
   (table `0xc068e840` is now seeded), the `(2,5)` factory null moves or clears,
   and CL4 advances **past** the UPDATE 7/8 frontier. Keep chasing the next fault
   via the QMP/`-d int` method already documented.

## Risks / open questions

* **Ctor internal faults on first real run.** Some constructors call deep helper
  chains (ctor[9] has 4 calls, 109 ins). If one of them *does* transitively read
  TPIDR before CL4 installs it, it could fault. Mitigation if that happens: run
  the constructors in **two waves** — the TPIDR-independent table seeders first
  (at least `ctor[2]`), let CL4 reach the point just after `msr tpidr_el0`
  (`0xc00aa728`, phys `rx+0xaa728`), and run the remainder from a second divert
  gated on that PC. The trampoline is unchanged; only the loader would compute a
  second gate PC and split `Larray`/`Larray_end`. This is the fallback, not the
  plan — static analysis shows no direct TPIDR use in any of the 11.
* **Scratch stack size.** 32 KiB is generous for C++ static ctors; if a ctor
  recurses unexpectedly, bump `CL4_SCRATCH_SZ`. The stack and code share the
  region; ensure `STACKTOP` (top) never grows down into the code at `+0x80`
  — 32 KiB vs 104 bytes gives ~32 KiB of headroom.
* **`0x698fc0` section offset.** Stable for this CL4 build; prefer the
  `macho_find_sect` form if you expect the component to be re-extracted.
* **PAC keys.** Assumes QEMU's guarded-domain PAC round-trips (it does today —
  CL4 already runs `retab`). The trampoline itself is PAC-free, so only the
  constructors' self-balanced `pacibsp/retab` matters, and that is unchanged from
  current behaviour.
* **Idempotency.** `ctor[1]` and similar are one-shot guarded; re-running is
  safe. The `g_cl4_ctors_done` one-shot prevents a second divert regardless.

## Files

* `gen_trampoline.py` — keystone generator; prints the C byte array + pool
  offsets, writes `trampoline.bin` / `trampoline.hex`.
* `trampoline.bin` / `trampoline.hex` — assembled 104-byte blob.
* `analyze_ctors.py` — capstone helper that reproduces every finding above
  (constructor bodies, registrar/factory/register, TPIDR scan, entry).
