# iOS 27 CL4 / Secure-World Bring-up (darwin-vm on Intel Mac)

Research work to make the iOS 27 (iPhone17,3 / t8140, 24A5430a) **DCP display**
coprocessor path work under [jprx/darwin-vm](https://github.com/jprx/darwin-vm) +
its `qemu-sptm` fork, by bringing up Apple's **exclave secure kernel ("CL4")** —
the SK domain that publishes `SecureRTBuddyDCP`, without which `RTBuddy(DCP)`,
`AppleDCPLinkServiceSoC` and `IOMobileFramebuffer` never attach and the screen
stays dark.

## ⚠️ Danger / legal
Per ChefKiss Inferno's notice: **no firmware, IVs, keys or decrypted images are in
this repo** (see `.gitignore`). Firmware acquisition/decryption is left to the user.
No AGPL Inferno code is copied; device models are written from GPL-2 references and
the QEMU changes are against the GPL-2 `qemu-sptm` fork.

## What's here
- `docs/RESUME-secure-world.md` — the live handoff doc. **Read this first.** Contains
  the breakthrough (CL4 now executes), the three QEMU guarded-domain fixes, the exact
  fault progression, and the current frontier (SPTM→SK domain handoff).
- `docs/FINDINGS-ios27-display.md` — full narrative log (Parts 1..45).
- `qemu-patches/qemu-sptm-cl4-all.patch` — all our `qemu-sptm` changes (CL4 loader in
  `hw/arm/xnuboot_sptm.c`, `-cl4` option, apple_regs CTRR/CTXR, and the 3 arch fixes).
- `qemu-patches/qemu-guarded-domain-fixes.patch` — just the 3 CPU-core fixes that make
  the guarded (SK/CL4) domain run (FP enable, Normal MMU-off memory, no forced align).
- `qemu-patches/BASE.txt` — the qemu-sptm base commit the patches apply onto.
- `scripts/parse_exclavecore.py` — parse/extract the DNUB exclavecore bundle
  (txtk/tadk/... components). Needs a firmware bundle you supply.
- `scripts/dt_fixup.py` — device-tree fixups (SPTM_DEBUG, DCP_REGION, NO_EXCLAVES…).
- `scripts/patch_rtbuddy_*.py` — XNU kernelcache RTBuddy/route patch experiments.
- `scripts/apple_rtkit.c`, `apple_dcp.c` — RTKit/AFK coprocessor emulator scaffolding.
- `rebuild-qemu.sh` — apply the patch onto a qemu-sptm checkout and build.

## The three QEMU guarded-domain fixes (key result)
All keyed on `env->currentg == 1` so only the guarded world (SPTM/TXM/SK "CL4") is
affected — baseline XNU boot is untouched:
1. `target/arm/helper.c` `fp_exception_el()`: guarded → FP/SIMD always accessible.
2. `target/arm/ptw.c` `get_phys_addr_disabled()`: guarded MMU-off memory = Normal WB.
3. `target/arm/tcg/hflags.c` `aprofile_require_alignment()`: guarded → no forced align.

With these, CL4 boots from its entrypoint through early init + a SIMD memcmp and into
domain registration (currently asserting on a bad domain id read from the SPTM→SK
handoff — see RESUME "UPDATE 4" and the notes on making __DATA physically contiguous
at `rx + 0x68c000`).

## Reproduce
See `docs/RESUME-secure-world.md` → "How to reproduce / debug".
