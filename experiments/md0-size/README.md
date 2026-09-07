# md0 ramdisk size truncation - iOS 27 (iPhone17,3 / t8140) XNU

**Goal:** boot the full iOS 27 rootfs (9.3 GB, `0x255A00000` bytes) as an `md0`
memory disk under the darwin-vm QEMU. XNU currently sizes the memory disk with a
**32‑bit** byte value, so a 9.3 GB image is seen as `0x255A00000 & 0xFFFFFFFF =
0x55A00000` (1.36 GB), and APFS mountroot fails:

```
apfs_vfsop_mountroot ... container size 10026483712 greater than device size 1436549120
mountroot ... error 92
```

* `10026483712 = 0x2_55A0_0000` - the real APFS container (from the superblock).
* `1436549120  = 0x5_5A00_000  = 0x55A00000` - what the `md0` block device reports.
* `0x255A00000 & 0xFFFFFFFF == 0x55A00000`. A clean 32‑bit truncation of a **byte**
  quantity.

This document pins the exact XNU instructions that truncate, explains the data
flow from the device‑tree `RAMDisk` region to the `md0` block count, and designs
the minimal Keystone‑backed kernel patch. **Analysis only - nothing here builds,
boots, or modifies the live darwin-vm / vphone-cli trees.**

Kernelcache analysed: `/Users/maliosdark/darwin-vm/firmware/bootkc`
(Mach‑O 64‑bit arm64e **FILESET**, 306 `LC_FILESET_ENTRY` kexts, 1551 segments).
All runtime panic/log addresses carry slide `0x20000000` (static = runtime −
`0x20000000`).

---

## 0. Segment / address model used for every citation

`scripts/macho_map.py` parses the top‑level mach header **and** every
`LC_FILESET_ENTRY` inner header, giving a vmaddr⇄fileoffset map across all
segments. Sanity check: the task's anchor `fo 0xc6463` maps to
`vmaddr 0xfffffff0070ca463` in `<TOP>/__PRELINK_TEXT` ✓.

Segments that matter here:

| owner | segment | vmaddr | fileoff | size | prot |
|---|---|---|---|---|---|
| `<TOP>` | `__PRELINK_TEXT` | `0xfffffff00700c000` | `0x8000` | `0xd94000` | r (cstring pool) |
| `<TOP>` | `__TEXT_EXEC` | `0xfffffff008400000` | `0x13fc000` | `0x2f54000` | r‑x |
| `com.apple.kernel` | `__TEXT_EXEC` | `0xfffffff00aa60000` | `0x03a5c000` | `0x8eb458` | r‑x |

The core XNU C code (`bsd/dev/memdev.c`, and the `mdevinit` caller) lives in
`com.apple.kernel/__TEXT_EXEC`; that fileset entry's bytes are the same bytes the
top‑level `__TEXT_EXEC` covers, so **a file offset such as `0x3c9140c` is the byte
offset in `bootkc`** and can be patched directly.

All the anchor strings ("RAMDisk", "ramdisk params @%s:%d", "mdevadd",
"memdev.c", "md%d", …) live in the merged `<TOP>/__PRELINK_TEXT` cstring pool
(`scripts/find_strings.py`).

---

## 1. The code that reads `RAMDisk` and creates `md0`

### 1a. The DT `RAMDisk` reader = the sole `mdevadd` caller (`mdevinit`)

`mdevadd` (see §3) is at **vmaddr `0xfffffff00ac94ff0`, fo `0x3c90ff0`**. A
BL‑scan across every executable fileset segment (`scripts` - callers scan) finds
**exactly one caller**:

```
BL mdevadd @ vmaddr 0xfffffff00b2be4d8   fo 0x42ba4d8   [com.apple.kernel]
```

That call sits inside the function that also references the `"RAMDisk"` and
`"ramdisk params @%s:%d"` strings (xref scan, `scripts/xref_fast.py`):

```
adrp+add -> 0xfffffff0070ca45b ("RAMDisk")             @ vmaddr 0xfffffff00b2be464  fo 0x42ba464
adrp+add -> 0xfffffff0070ca463 ("ramdisk params @%s:%d") @ vmaddr 0xfffffff00b2bf40c  fo 0x42bb40c
```

So this function **is** `mdevinit` (compiled as PAC‑heavy C++/IOKit in iOS 27 - it
reaches the `RAMDisk` property through IORegistry `getProperty`‑style virtual
calls rather than the classic `SecureDTGetProperty`, but the semantics are
identical: look up the `/chosen/memory-map` `RAMDisk` entry, then `mdevadd` it).

> Note on xref methodology: a first pass with capstone's ADD operand‑tracking
> found **0** xrefs because a full linear sweep of `__TEXT_EXEC` desyncs at literal
> pools. The reliable finder decodes each fixed 4‑byte ARM64 slot (or scans raw
> words). `scripts/xref_fast.py` (raw‑word ADRP/ADD/ADR/LDR decoder) is the source
> of truth for every xref quoted here.

### 1b. The `RAMDisk` `{paddr,length}` read, right before the `mdevadd` call

`scripts/disasm.py 0xfffffff00b2be440 0xfffffff00b2be4e0`:

```
0xb2be46c  blraa  x8, x16                 ; x0 = getProperty("RAMDisk")  (x1 = &"RAMDisk")
0xb2be470  cbz    x0, skip                ; no RAMDisk property -> no md0
0xb2be48c  blraa  x8, x16                 ; x0 = bytes of the {u64 paddr, u64 length} struct
0xb2be490  ldr    x8, [x0, #8]            ; x8 = length  (64-bit load)
0xb2be494  mov    x9, #0xfffffff0000
0xb2be498  movk   x9, #0xf001            ; x9 = 0x0000_0FFF_FFFF_F001 (sanity bound)
0xb2be49c  cmp    x8, x9
0xb2be4a0  b.hs   error
0xb2be4a4  mov    x28, x0                 ; x28 = &{paddr,length}
0xb2be4a8  ldr    x0, [x0]                ; x0 = paddr           (struct +0)
0xb2be4b4  bl     0xb3281cc               ; paddr -> phys/page helper (result @ sp+0x48)
0xb2be4b8  ldr    x8, [sp, #0x48]
0xb2be4bc  lsr    x8, x8, #0xc            ; base page  (64-bit)
0xb2be4c4  csel   x1, x8, xzr, eq         ; arg2 base  (pages)
0xb2be4c8  ldr    x8, [x28, #8]           ; x8 = length          (struct +8, 64-bit load)
0xb2be4cc  lsr    x2, x8, #0xc            ; arg3 SIZE = length >> 12  (PAGES, 64-bit) <-- NOT truncated
0xb2be4d0  mov    w0, #-1                 ; arg1 devid = -1 (auto-assign)
0xb2be4d4  mov    w3, #0                  ; arg4 phys  = 0
0xb2be4d8  bl     mdevadd
```

**Key result:** at the `mdevadd` call the length is read as a **full 64‑bit** value
(`ldr x8,[x28,#8]`) and converted to a page count with a **64‑bit** shift
(`lsr x2,x8,#0xc`). For 9.3 GB, `x2 = 0x255A00` pages. **No truncation happens on
the DT‑read → mdevadd path.** The loader's u64 length survives intact to here.

---

## 2. `mdevadd`'s signature and the `mdev[]` record

`mdevadd` prologue at **`0xfffffff00ac94ff0` / fo `0x3c90ff0`**
(`scripts/disasm.py 0xfffffff00ac94ff0 0xfffffff00ac95240`):

```
mov  x20, x3     ; arg4 phys
mov  x19, x2     ; arg3 size
mov  x21, x1     ; arg2 base
...              ; arg1 devid in w0 (tbnz w0,#0x1f -> negative => auto-assign)
0xac9507c  add  x9, x21, w19, uxtw   ; base + (size as 32-bit unsigned)  -- overlap math
...
0xac951dc  str  x21, [x23]           ; mdev[i].mdBase = base       (uint64,  +0x00)
0xac951f8  str  w19, [x23, #8]       ; mdev[i].mdSize = size       (uint32,  +0x08)  <-- page count
```

So the prototype is the classic:

```c
dev_t mdevadd(int devid, uint64_t base, unsigned int size /* PAGES */, int phys);
struct mdev { uint64_t mdBase; unsigned int mdSize; int mdFlags; int mdSecsize; ... } mdev[16]; // stride 0x30
```

* `mdSize` is a **page count** in a **uint32** field (`str w19,[x23,#8]`; every reader
  is `ldr w`). `9.3 GB = 0x255A00 pages` ⇒ **fits in 32 bits** - `mdSize` is stored
  **correctly**. `mdBase` is uint64 (`str x21`).
* Therefore, as the task hypothesised in step 3, **the truncation is NOT in mdevadd
  and NOT in the page‑count**. It is downstream, wherever `mdSize` is converted
  **back to a byte size with a 32‑bit `<< 12`** (`0x255A00 << 12 = 0x2_55A0_0000`
  overflows 32 bits → `0x55A00000`).

`mdev[]` base address (semantic anchor only): `adrp x?,0xfffffff00b699000 ; add
#0xab0` ⇒ **`0xfffffff00b699ab0`**.

---

## 3. The EXACT truncation instructions

A semantic finder (`scripts/patch_md0_size.py::find_mdev_size_shift_sites`) scans
`com.apple.kernel/__TEXT_EXEC` for the pattern *"a value loaded from the mdSize
field `[entry+8]` (`ldr w<s>,[x<e>,#8]`) that is then shifted left by 12 in a
**32‑bit** register"* - i.e. `lsl w<s>,w<s>,#0xc` or `add w<d>,w<x>,w<s>,lsl #12`.
It finds **four** sites (nothing hardcoded - all located by the anchor):

### Site A - `mdevioctl` `DKIOCGETBLOCKCOUNT` (THE mountroot blocker)

vmaddr `0xfffffff00ac95404`, fo `0x3c91404`:

```
0xac95404  ldr  w9, [x8, #8]           ; w9 = mdSize (pages) [zero-extends x9]
0xac95408  ldr  w8, [x8, #0x10]        ; w8 = mdSecsize      [zero-extends x8]
0xac9540c  add  w9, w8, w9, lsl #12    ; w9 = secsize + (mdSize<<12)   <-- 32-bit TRUNCATES
0xac95410  sub  w9, w9, #1
0xac95414  udiv w8, w9, w8             ; w8 = blockcount = ((mdSize<<12)+secsize-1)/secsize
0xac95418  str  x8, [x19]             ; *(uint64_t*)data = blockcount
```

This is the C statement
`*(uint64_t*)data = ((mdev[devid].mdSize << 12) + mdev[devid].mdSecsize - 1) / mdev[devid].mdSecsize;`
where `mdSize` is `unsigned int`, so `mdSize << 12` is evaluated in 32‑bit and
overflows. With `mdSize=0x255A00`, `secsize=512`:

```
(0x255A00 << 12) 32-bit = 0x55A00000
(0x55A00000 + 511)/512   = 0x2AD000 blocks
APFS device size = 0x2AD000 * 512 = 0x55A00000 = 1436549120   <-- EXACT panic number
```

**This is the instruction that produces "device size 1436549120".** The dependent
`sub`/`udiv` (0xac95410/0xac95414) operate on the already‑truncated value, so they
must be widened together.

### Site B - I/O transfer clamp (`mdevrw`/strategy, read path)

vmaddr `0xfffffff00ac95530`, fo `0x3c91530`:

```
0xac95530  ldr  w9, [x9, #8]      ; mdSize (pages)
0xac95534  lsl  w9, w9, #0xc      ; device bytes            <-- 32-bit TRUNCATES (zeros x9[63:32])
0xac95538  sub  w11, w9, w8       ; remaining = devbytes - offset
0xac9553c  cmp  w10, w11
0xac95540  csel w10, w10, w11, lt ; clamp request to remaining
0xac95544  cmp  x8, x9            ; offset(64) vs devbytes(x9 truncated)  <-- wrong past 1.36 GB
0xac95548  csel w8, wzr, w10, gt
```

### Site C - I/O offset bounds check (strategy)

vmaddr `0xfffffff00ac9568c`, fo `0x3c9168c`:

```
0xac95684  ldrsw x10, [x20, #0x10]  ; mdSecsize
0xac95688  mul   x19, x9, x10       ; byte offset = blkno * secsize   (64-bit)
0xac9568c  ldr   w9, [x20, #8]      ; mdSize (pages)
0xac95690  lsl   w9, w9, #0xc       ; device bytes          <-- 32-bit TRUNCATES
0xac95694  cmp   x19, x9            ; offset >= devbytes ?  -> rejects I/O past 1.36 GB
0xac95698  b.hs  out_of_range
0xac956a0  cmp   x8, x9             ; (also truncated)
```

### Site D - `mdevinit`'s global record of the ramdisk byte‑extent

vmaddr `0xfffffff00b2beebc`, fo `0x42baebc` (inside `mdevinit`, right after the
`mdevadd` call):

```
0xb2beeac  ldr  x8, [x20]          ; mdBase (pages)
0xb2beeb0  lsl  x8, x8, #0xc       ; base BYTES              (64-bit - CORRECT)
0xb2beeb8  str  x8, [x9, #0x158]   ; g_ramdisk_base = base_bytes   (@0xfffffff00b6c0158)
0xb2beebc  ldr  w8, [x20, #8]      ; mdSize (pages)
0xb2beec0  lsl  w8, w8, #0xc       ; size BYTES              <-- 32-bit TRUNCATES (asymmetric!)
0xb2beec8  str  x8, [x9, #0x160]   ; g_ramdisk_size = size_bytes   (@0xfffffff00b6c0160)
```

The **base** store immediately above uses a 64‑bit `lsl x8`; the **size** store
uses a 32‑bit `lsl w8` - a clear asymmetric source bug (a `uint32_t` where the
line above is `uint64_t`). The global pair `{0xb6c0158 base, 0xb6c0160 size}` is
**read ~30 times across the kernel** (xref scan) - it is the kernel's byte‑extent
record of the ram disk (consumed by memory/pager/imageboot bookkeeping). The
"no ramdisk" path zeros both (`str xzr` @ 0xb2bed1c/0xb2bed24), so 0xb2beec0 is the
only real truncation for this global.

> Downstream widths that DON'T need changing: `mdSize` (uint32 page count) holds
> up to `2^32 pages = 16 TB`; the block‑count result is stored 64‑bit
> (`str x8,[x19]`); per‑I/O transfer counts are ≤ MAXPHYS. Only the four 32‑bit
> `<<12` byte computations truncate.

---

## 4. The fix - minimal Keystone‑backed widen (w → x)

Every truncation is a single instruction that shifts/adds a page count into a byte
size in a **32‑bit** register. The fix is to re‑encode those instructions (and the
two ops that depend on Site A's result) in their **64‑bit** form. Each edit is
4 bytes → 4 bytes, same location, so no relayout/re‑sign of the macho is needed
(the darwin-vm SPTM path accepts a patched kernelcache - RESUME‑secure-world.md
"Reusable techniques"). The two `ldr w` field loads already zero‑extend the full
`x` register, so they are left unchanged.

`scripts/patch_md0_size.py` produces this plan (bytes from Keystone `asm()`,
verified by capstone round‑trip):

| # | role | vmaddr | fo (bootkc) | before | after | bytes |
|---|---|---|---|---|---|---|
| A1 | blockcount | `0xac9540c` | `0x3c9140c` | `add w9, w8, w9, lsl #12` | `add x9, x8, x9, lsl #12` | `0931090b`→`0931098b` |
| A2 | blockcount | `0xac95410` | `0x3c91410` | `sub w9, w9, #1` | `sub x9, x9, #1` | `29050051`→`290500d1` |
| A3 | blockcount | `0xac95414` | `0x3c91414` | `udiv w8, w9, w8` | `udiv x8, x9, x8` | `2809c81a`→`2809c89a` |
| B  | I/O clamp | `0xac95534` | `0x3c91534` | `lsl w9, w9, #0xc` | `lsl x9, x9, #0xc` | `294d1453`→`29cd74d3` |
| C  | I/O bounds | `0xac95690` | `0x3c91690` | `lsl w9, w9, #0xc` | `lsl x9, x9, #0xc` | `294d1453`→`29cd74d3` |
| D  | ramdisk-extent global | `0xb2beec0` | `0x42baec0` | `lsl w8, w8, #0xc` | `lsl x8, x8, #0xc` | `084d1453`→`08cd74d3` |

**Note (guardrail‑critical):** the `lsl w,w,#0xc → lsl x,x,#0xc` widening is **not a
single sf‑bit flip**. 32‑bit `LSL #imm` is `UBFM` (`…53`) and the 64‑bit form uses a
different N/immr/imms bitfield (`…d3`), so the bytes change from `294d1453` to
`29cd74d3`. This is exactly why the replacement must come from Keystone `asm(...)`,
never a hand‑edited byte. (The `add`/`sub`/`udiv` widenings *are* just the sf bit,
but they are produced by Keystone too for uniformity.)

### Fix scope / ordering

* **Minimum to pass mountroot:** Site A (A1+A2+A3). This alone makes
  `DKIOCGETBLOCKCOUNT` report `0x12AD000` blocks ⇒ device size `0x255A00000` =
  10026483712, so APFS's "container ≤ device" check passes.
* **Required for a *usable* 9.3 GB md0:** Sites B and C as well - otherwise reads to
  offsets/lengths beyond `0x55A00000` are clamped (B) or rejected as out‑of‑range
  (C), and APFS metadata near the end of the container (checkpoints/spaceman)
  can't be read, so mount/boot fails after the size check. Fix A+B+C together.
* **Recommended for correctness:** Site D, so the kernel's widely‑read ramdisk
  byte‑extent global matches reality and to remove the base/size asymmetry.

All four are the *same* one‑line widening, so patch all six instructions.

### This is a clean single‑widen fix (not a hard 32‑bit design)

The md‑device design is **not** fundamentally 32‑bit: `mdSize` is already a
page‑count that comfortably holds 9.3 GB (indeed up to 16 TB), the block count is
stored in a `uint64_t`, and offsets are computed 64‑bit. Only four
byte‑size expressions were compiled with a 32‑bit `<<12`. Widening them is
sufficient; **no** structure field needs to grow and **no** alternative (real block
device / sub‑4 GB rootfs) is required. If a future kernelcache instead stored
`mdSize` itself in bytes as `uint32`, that would be a hard 32‑bit design - but this
one is not.

---

## 5. How to apply / validate (design; not executed here)

1. Retarget on the exact `bootkc` under test by re‑running the **semantic finder**
   (`scripts/patch_md0_size.py`) - it re‑derives the six offsets from the
   `ldr w,[entry+8]` + 32‑bit `<<12` anchor; **do not** trust the offsets in the
   table above against a different build.
2. `python scripts/patch_md0_size.py --emit-bytes <copy-of-bootkc>` writes a patched
   **copy** (the six words differ, file size unchanged). Verify by disassembling the
   six offsets → all `x`‑form.
3. Boot darwin-vm with the patched `bootkc` and the 9.3 GB image as `-ramdisk`
   (`rd=md0`). Expect `DKIOCGETBLOCKCOUNT` → `0x12AD000`, device size `0x255A00000`,
   and the `container size … greater than device size` panic gone.
4. Per vphone-cli `CLAUDE.md` ("For any changes applying new patches, also update
   research/0_binary_patch_comparison.md"): when this graduates from design to an
   applied patcher, add a `patch_md0_ramdisk_size` row to
   `research/0_binary_patch_comparison.md` describing the four‑site w→x widen.
   *(Not done here - this task is analysis/design only and must not modify the live
   tree.)*

---

## 6. Scripts (all under `scripts/`, use the vphone-cli venv)

Run with `/Users/maliosdark/vphone-cli/.venv/bin/python` (capstone 5.0.7,
keystone 0.9.2).

* `macho_map.py` - FILESET parser; vmaddr⇄fileoffset across all segments + kexts.
* `find_strings.py` - locate the anchor cstrings and their vmaddrs.
* `xref_fast.py` - raw‑word ADRP+ADD / ADR / ADRP+LDR xref scanner (alignment‑safe).
* `disasm.py <va_start> <va_end>` - annotated disassembler (string refs, BL targets).
* `patch_md0_size.py [--emit-bytes OUT]` - **semantic** finder + Keystone widen plan;
  prints before/after for all six edits; optionally writes a patched copy.

### Reproduction one‑liners

```bash
V=/Users/maliosdark/vphone-cli/.venv/bin/python
D=/Users/maliosdark/ios27-cl4-secure-world/experiments/md0-size/scripts
$V $D/find_strings.py                 # anchor strings -> vmaddr
$V $D/xref_fast.py                    # RAMDisk / ramdisk-params / memdev xrefs
$V $D/disasm.py 0xfffffff00b2be440 0xfffffff00b2be4e0   # RAMDisk read -> mdevadd
$V $D/disasm.py 0xfffffff00ac95404 0xfffffff00ac9541c   # Site A (blockcount)
$V $D/patch_md0_size.py               # the widen plan (design run, no writes)
```
