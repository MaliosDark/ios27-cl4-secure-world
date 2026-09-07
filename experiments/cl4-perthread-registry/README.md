# CL4 per-thread registry - the `(2,5)` lookup fault

Analysis + fix design for the fault reached after the `__mod_init_func`
constructor-runner (RESUME UPDATE 14): CL4 main init calls a `(2,5)` singleton
accessor whose per-thread registry list is empty, returns `NULL`, and the caller
dereferences `[NULL+0x2a0]`.

> **Scope:** analysis + code/design only. Nothing here builds QEMU, boots, or
> edits the live `/Users/maliosdark/darwin-vm/qemu-sptm` tree. The integration is
> written as a **patch to apply later**.

All addresses are cited as `vmaddr` (CL4 image base `0xc0000000`) **and** file
offset / physical:

| space | rule |
|---|---|
| file offset (`txtk`) | `fileoff = vmaddr - 0xc0000000` |
| physical (MMU-off, contiguous load, RESUME U5) | `phys = 0x10006884000 + (vmaddr - 0xc0000000)` |
| `__DATA` (`tadk`) | vmaddr `0xc068c000`, file-backed `0xc068c000..0xc06d4000`; higher = **bss (zero)** |

Reproduce every finding: `source /Users/maliosdark/vphone-cli/.venv/bin/activate`
then run the scripts in `scripts/` (see [Scripts](#scripts)).

---

## TL;DR

* **Registration function:** `register(node)` @ **`0xc00a1e20`** (phys
  `0x10006925e20`). Lock-free `casl` push of a caller-owned node onto the
  per-thread list whose head is `[ [tpidr_el0+0x10] + 0 ]`. Signature:
  `void register(node*)` - the node already holds `{next@0, key1@8(u32),
  key2@0x10(u32), value@0x18(u64)}`. (Variant `0xc00a1e04` registers the fixed
  static node `0xc068e7f8` = key `(1,1)`.)
* **The `(2,5)` entry:** static node template **`0xc068d668`** (`key1=2,key2=5`),
  registered by function **`0xc00982e0`** at call site **`0xc0098340`**, with
  **`value = 0xc06fece8`** (a `__DATA` **bss** singleton object; phys
  `0x10006f82ce8`). The accessor returns `[value+0x2a0]`.
* **Who registers it & when:** `0xc00982e0` is called at **`0xc00a7178`**, deep
  inside the **domain-setup / domain-enter handler `0xc00a6ea4`** (phys
  `0x1000692aea4`), *after* that function installs the **real** per-thread
  context and TPIDR (via setter `0xc00aa724` at call `0xc00a7114`). Domain-setup
  is invoked from CL4's entry init at **`0xc00996bc`** (`blr x5`, `x5=0xc00a6ea4`).
* **Root cause of our fault:** the ctor-runner pre-installs a **non-zero fake
  TPIDR** before entry. Both the entry stack-setup (`0xc00a7b3c`) and domain-setup
  (`0xc00a6ea4`) branch on `tpidr_el0 == 0` to decide *"first entry → build the
  real per-thread context and register the base services."* A non-zero fake TPIDR
  forces the *"already have a context"* path, so the real context build **and the
  base-service registration (including `(2,5)`) are skipped** - every base
  `(k1,k2)` singleton stays unregistered.
* **Fix (root-cause-faithful):** after the constructor pass, **zero `TPIDR_EL0`**
  before branching to CL4 entry, so CL4's own domain-setup runs its build path and
  registers `(2,5)` (and the rest) itself. Deterministic fallback: pre-seed the
  fake context's list with the `(2,5)` node (exact bytes below).

---

## 1. The registry mechanism (verified)

### 1.1 Lookup - factory `0xc00a1e70` (phys `0x10006925e70`)

```asm
mrs  x8, tpidr_el0
ldr  x8, [x8, #0x10]     ; x8 = REGOBJ  = [tpidr+0x10]
ldr  x9, [x8]            ; x9 = HEAD    = [REGOBJ+0]   (first node)
cbz  x9, .miss
.loop:
ldr  w10, [x9, #8]       ; key1
ldr  w11, [x9, #0x10]    ; key2
ldr  x12, [x9, #0x18]    ; value
cmp  w11, w1             ; key2 == arg1
ccmp w10, w0, #0, eq     ; key1 == arg0
csel x8,  x12, x8, eq    ; if match -> remember value
ldr  x9,  [x9]           ; x9 = node->next
cbnz x9,  .loop
```

`(key1,key2)` are **32-bit**; the node's high halves are ignored. So the node
ABI is:

```
+0x00  next   u64   ; 0 = end
+0x08  key1   u32   ; factory arg x0
+0x10  key2   u32   ; factory arg x1
+0x18  value  u64   ; returned pointer
```

Wrapper **`0xc00a0e58`** (phys `0x10006924e58`) is a *get-or-cache*:
`if(!*cache){ *cache = factory(k1,k2); } return *cache;`. Callers pass the cache
cell in `x0` and `(k1,k2)` in `(w1,w2)`.

### 1.2 The `(2,5)` accessor `0xc0098ce0` (phys `0x1000691cce0`) - the fault

```asm
adrp x0, 0xc06fe000 ; add x0,x0,#0xce0   ; cache cell 0xc06fece0
mov  w1, #2 ; mov w2, #5
bl   0xc00a0e58                          ; wrapper(cache, 2, 5)
ldr  x0, [x0, #0x2a0]                     ; <-- FAULT: x0==NULL when list empty
retab
```

It is one of a **large family** (`0xc0098530`, `0xc0098d0c`, `0xc0098e8c`, …) that
all look up `(2,5)` and read different fields of the same singleton - i.e. `(2,5)`
is a big shared object. Its canonical address is `value = 0xc06fece8`
(cache cell `0xc06fece0`; the object sits at cache+8).

### 1.3 Registration - `register(node)` `0xc00a1e20` (phys `0x10006925e20`)

```asm
mrs  x8, tpidr_el0
ldr  x8, [x8, #0x10]     ; x8 = REGOBJ
...
.retry:
ldr  x10, [x8]           ; old head
str  x10, [x0]           ; node->next = old head     (x0 = node)
casl x11, x0, [x8]       ; [REGOBJ] = node  (CAS)
cmp  x11, x10 ; b.ne .retry
retab
```

Signature `void register(node* x0)`; the node's `key1/key2/value` are filled by
the caller **before** the call. Confirmed by `scripts/find_insert.py` +
`scripts/reg_keys.py`. The 11 register call sites are lazy singletons of the shape
`lookup(k1,k2); if(null){ fill static node; register(node); }` covering keys
`(4,4)(4,8)(4,0xa)(4,0xb)(4,0xc)(4,0xd)(2,6)` plus the domain-setup batch.

### 1.4 The `(2,5)` registrar - `0xc00982e0` (phys `0x1000691c2e0`)

```asm
mov w0,#4 ; mov w1,#4 ; bl 0xc00a1e70 ; cbnz x0, .done   ; idempotency guard on (4,4)
adrp x0,0xc068d648 ; str x19,[x0,#0x18] ; bl 0xc00a1e20   ; register (2,4) value=x19(arg)
adrp x0,0xc068d668 ; adrp x8,0xc06fece8 ; str x8,[x0,#0x18] ; bl 0xc00a1e20  ; register (2,5) value=0xc06fece8
...                                                          ; continues (2,4),(4,4),… lookups
```

Static node templates (in `tadk`, pre-filled `key1/key2`, `value` filled at
runtime):

| node vmaddr | phys | key1 | key2 | value (runtime) |
|---|---|---|---|---|
| `0xc068d648` | `0x10006f11648` | 2 | 4 | `x19` = registrar arg (`[handoff+0x10]`) |
| **`0xc068d668`** | **`0x10006f11668`** | **2** | **5** | **`0xc06fece8`** (phys `0x10006f82ce8`) |
| `0xc068d6b8` | `0x10006f116b8` | 2 | 1 | (runtime) |
| `0xc068d6d8` | `0x10006f116d8` | 2 | 2 | (runtime) |
| `0xc068e7f8` | `0x10006f127f8` | 1 | 1 | (runtime, via `0xc00a1e04`) |

---

## 2. Ordering - who registers `(2,5)` and when

Call graph (all verified with `scripts/cl4dis.py bl <addr>`):

```
CL4 entry 0xc00994f0
  └─ 0xc009968c  blr 0xc00a7b3c        (per-thread stack setup; branches on tpidr==0)
  └─ 0xc00996bc  blr x5 = 0xc00a6ea4   (DOMAIN-SETUP / domain-enter handler)
        0xc00a6ee0  cbz tpidr, .build          ; tpidr==0 -> build real context
        .build (0xc00a700c):
             ... memcpy the 0x118-byte domain descriptor ...
             0xc00a7114  bl 0xc00aa724          ; msr tpidr_el0 = new context  (REAL TPIDR)
             0xc00a7118  stp x26,x25,[x24]
             0xc00a711c  b   0xc00a6ee4          ; re-enter with tpidr now valid
        .have_ctx (0xc00a6ee4 …):
             0xc00a6f74  str x9,[tpidr+0x10]     ; install REGOBJ (empty list head)
             0xc00a6f88  bl 0xc00a1e04           ; register (1,1)
             0xc00a6f98  bl 0xc009a008           ; parse SPTM->SK handoff tags -> x23
             ...
             0xc00a7178  bl 0xc00982e0           ; register (2,4),(2,5),(4,4)  <-- (2,5) born here
```

The `(2,5)` **accessors run later**, from indirectly-dispatched event/message
handlers (`0xc0097e3c` → `0xc00a5454` → `0xc00aa9d0` → `0xc0098ce0`, and the
`svc`-issuing handler `0xc00a1b24`); no direct `BL` reaches them from entry, so on
real hardware they fire only **after** a thread has entered its domain - i.e.
**after** `0xc00a6ea4` populated the list. Ordering on real HW:

```
build real context  →  install real TPIDR  →  register (1,1)(2,4)(2,5)(4,4)…  →  (2,5) lookups succeed
```

### Why our synthesized boot faults

The ctor-runner (UPDATE 14) installs `TPIDR_EL0 = g_cl4_tpidr` (a **non-zero**
fake context) and leaves it installed when it branches to CL4 entry. Therefore:

* `0xc00a6ea4`'s `cbz tpidr, .build` at `0xc00a6ee0` is **not taken** → the
  `.build` path (which installs the real TPIDR *and* whose continuation reaches
  `0xc00a7178`, the `(2,5)` registrar) is entered on the *wrong* footing, and the
  first-entry registration of the base services never happens against a correct
  context. The per-thread list stays empty.
* A later `(2,5)` accessor then finds an empty list → `NULL` → `[NULL+0x2a0]`
  data abort (FAR `0x2a0`), exactly as observed.

This is an **ordering/handoff defect, not a missing value**: registration is
supposed to *precede* lookup, driven by CL4's own domain-setup on the
`tpidr==0` first-entry path, which the pre-installed fake TPIDR suppresses.

Confirmed safe to zero TPIDR before entry: the only TPIDR readers between entry
and domain-setup are `0xc00a7b3c` and `0xc00a6ea4`, and **both have explicit
`tpidr==0` branches** (`0xc00a7b58`, `0xc00a6ee0`) that are the intended
first-entry paths. Nothing in the entry prologue reads TPIDR
(`scripts/cl4dis.py` scan: 0 sites in `0xc00994f0..0xc00996c0`).

---

## 3. The fix

### Option (a) - RECOMMENDED, root-cause-faithful: zero TPIDR after the ctor pass

Let the constructors run with the fake TPIDR (they need `[tpidr+8]`/`[tpidr+0x10]`
readable - e.g. the ctor helper `0xc00a6ca4` does `ldr x0,[tpidr+8]`), then set
`TPIDR_EL0 = 0` **before** branching to CL4 entry. CL4's `0xc00a6ea4` then takes
its `.build` path, installs the real context/TPIDR (`0xc00aa724`), and registers
`(2,5)` via `0xc00982e0` - the faithful reproduction of hardware order. Keep the
existing domain-descriptor **x1 probe** in place; the build path still consumes
the SK handoff/descriptor.

**Integration (apply later to `qemu-sptm`):**

* `target/arm/tcg/helper-a64.c`, `HELPER(exception_return)` - in the one-shot CL4
  handoff that currently diverts to the trampoline and sets
  `env->cp15.tpidr_el[0] = g_cl4_tpidr`: this stays as-is *for the trampoline
  run*. Add a **second** one-shot, keyed on the trampoline's *final* `br entry`
  (or on `g_cl4_ctors_done` becoming set and PC == `g_cl4_entry_pc`), that sets
  `env->cp15.tpidr_el[0] = 0` right before CL4 entry executes. Simplest concrete
  form: have the trampoline itself `msr tpidr_el0, xzr` as its penultimate
  instruction (see below) so no extra hook is needed.
* `hw/arm/xnuboot_sptm.c` - no data changes required for (a). Optionally drop the
  fake-context list plumbing once (a) is confirmed (the ctors still need the fake
  ctx while they run, so keep `g_cl4_tpidr` and the ctx; only its *lifetime*
  shrinks to the trampoline).

**Trampoline change (preferred, self-contained):** in
`experiments/cl4-ctor-runner/gen_trampoline.py`, insert `msr tpidr_el0, xzr`
(`0xd51bd05f`) in the keystone source immediately before the final `br entry`
(after the `mov x0,x19 ; mov x1,x20 ; mov sp,xzr` epilogue at trampoline `+0x30`).
The current trampoline tail is:

```
+0x30  mov  x1, x20
+0x34  mov  x9, xzr ; +0x38 mov sp, x9      ; SP <- 0
+0x3c  ldr  x16, [pool:entry]               ; <-- add "msr tpidr_el0, xzr" BEFORE this
+0x40  br   x16
```

Because the four `ldr` literals are PC-relative, add the instruction **in the
keystone source (via labels)** and let `gen_trampoline.py` re-emit - do **not**
byte-patch, or the literal-pool offsets shift. The trampoline grows 104 → 108
bytes, so bump the loader's copy length / dummypage trampoline slot by 4. The
ctors have already run with the fake TPIDR; zeroing it hands CL4 entry the
`tpidr==0` first-entry state. `g_cl4_tpidr` and the fake ctx stay as-is.

**Validation:** boot with `-cl4` + the ctor-runner + the tpidr-zero. Expected:
`0xc00a6ea4` now takes `0xc00a6ee0 → 0xc00a700c` (`-d exec` shows the `.build`
path and a `bl 0xc00aa724`), then `bl 0xc00982e0` at `0xc00a7178`; the `(2,5)`
data-abort at `0x1000691cd00` (FAR `0x2a0`) is gone. New frontier = whatever
domain-setup's build path or the next base service needs.
Risk: the build path (`0xc00a700c`) may hit its own missing-handoff fault; if so,
fall back to (b) to keep moving, and reverse the build path separately.

### Option (b) - deterministic FALLBACK: pre-seed the `(2,5)` node

Keep the fake TPIDR; pre-link the `(2,5)` node into the fake context's list so the
factory finds it. Only fixes `(2,5)` (the immediate fault); expect the next base
key `(2,4)/(4,4)/(2,6)/(1,1)` to fault next (whack-a-mole - hence (a) is
preferred). Exact writes (from `scripts/gen_perthread_seed.py`; `dummypage` is the
scratch VA, `dummypage_phys` its physical base, `g_cl4_tpidr = dummypage_phys +
0x200`):

```c
/* regobj + one-node list in the dummypage scratch (offsets are examples;
   place them anywhere unused past the trampoline/stack). */
*(uint64_t*)(dummypage + 0x210) = dummypage_phys + 0x400; /* [ctx+0x10] = regobj  */
*(uint64_t*)(dummypage + 0x400) = dummypage_phys + 0x420; /* [regobj]   = head    */
*(uint64_t*)(dummypage + 0x420) = 0x0;                    /* node.next  = end     */
*(uint32_t*)(dummypage + 0x428) = 2;                      /* node.key1  = 2       */
*(uint32_t*)(dummypage + 0x430) = 5;                      /* node.key2  = 5       */
*(uint64_t*)(dummypage + 0x438) = 0x10006f82ce8;          /* node.value = phys(0xc06fece8) */
```

`value = phys(0xc06fece8) = 0x10006f82ce8` is CL4's canonical `(2,5)` object
(bss, zero-filled), so `[value+0x2a0] = 0`; the immediate accessor's caller
(`0xc00a1b24`) tolerates `NULL` (`cbz x0`). To extend the seed to the other base
services, add nodes `(2,4)/(2,1)/(2,2)/(1,1)` the same way (values unknown → point
at zeroed scratch), but note their downstream accessors may read non-null fields
and fault - which is precisely why (a) is the right long-term fix.

`hw/arm/xnuboot_sptm.c` - perform the writes above right after the fake context is
built (next to the existing `g_cl4_tpidr` setup), guarded by the same
`CL4_NO_CTORS`-style env so it can be toggled.

### Option (c) - the missing input, stated plainly

The missing handoff input is **not a data blob** but a **register precondition**:
`TPIDR_EL0` must be `0` at CL4 entry (as SPTM/GXF leaves it on a cold thread), so
CL4's domain-setup performs first-entry context construction and base-service
registration. Our loader supplies a non-zero TPIDR for the ctor pass and forgets
to clear it. Option (a) *is* the implementation of (c).

---

## 4. Update the ctor-runner note

`experiments/cl4-ctor-runner/README.md` §2 says *"No manual per-thread-context or
registry-head allocation is required … CL4 does this itself once the static
descriptor tables … let domain setup proceed."* That is correct **and** implies
the corollary this experiment proves: the fake TPIDR the runner installs for the
ctors must be **torn down (zeroed) before entry**, or domain-setup's first-entry
path - the very path that "does this itself" - is skipped. Add the `msr
tpidr_el0, xzr` to the trampoline tail.

---

## Scripts

| script | what it does |
|---|---|
| `scripts/cl4dis.py` | disasm + xref lib: `dis <vm> [n]`, `bl <target>`, `adrp <page>`, `msr` |
| `scripts/find_registrar.py` | tpidr-reading functions that store a node shape |
| `scripts/find_node_build.py` / `find_node2.py` | node-field store scanners (show registration is via a helper, not inline stores) |
| `scripts/classify_tpidr.py` | classify tpidr functions read vs write; finds `0xc00a6ea4` writing `[tpidr+0x10]` |
| `scripts/find_insert.py` | head-insert idiom + callers of the `(2,5)` accessor |
| `scripts/find_reg2.py` | 2-level taint through `[tpidr+0x10]`/`[tpidr+0xf8]` |
| `scripts/reg_keys.py` | resolve every `register()` call's node keys/values |
| `scripts/gen_perthread_seed.py` | emit option-(b) node bytes + loader writes for a given `dummypage_phys` |

Run any with the project venv:
`source /Users/maliosdark/vphone-cli/.venv/bin/activate && python3 scripts/<x>.py`.

## Address quick-reference (vmaddr → phys)

```
register(node)        0xc00a1e20  0x10006925e20
register-static(1,1)  0xc00a1e04  0x10006925e04
factory  lookup       0xc00a1e70  0x10006925e70
wrapper  get-or-cache 0xc00a0e58  0x10006924e58
(2,5) accessor        0xc0098ce0  0x1000691cce0   (faults at +0x20 = 0x1000691cd00)
(2,5) registrar       0xc00982e0  0x1000691c2e0   (register call @0xc0098340)
domain-setup handler  0xc00a6ea4  0x1000692aea4   (registrar call @0xc00a7178)
  tpidr==0 branch     0xc00a6ee0                  (-> build path 0xc00a700c)
  real TPIDR install  0xc00a7114 -> 0xc00aa724     (msr tpidr_el0)
entry -> domain-setup 0xc00996bc  (blr x5=0xc00a6ea4)
stack-setup           0xc00a7b3c  0x1000692db3c   (tpidr==0 branch @0xc00a7b58)
node(2,5) template    0xc068d668  0x10006f11668
(2,5) object          0xc06fece8  0x10006f82ce8
(2,5) cache cell      0xc06fece0  0x10006f82ce0
```
