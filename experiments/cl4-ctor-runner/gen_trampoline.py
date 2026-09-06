#!/usr/bin/env python3
# gen_trampoline.py — assemble the CL4 __mod_init_func runner trampoline.
#
# Emits a small position-independent ARM64 (AArch64) code blob that, when
# executed in CL4's guarded EL1 context (MMU OFF, physical addressing), calls
# each of CL4's 11 __DATA,__mod_init_func constructors in array order and then
# branches to the real CL4 entrypoint.
#
# The blob is FULLY position-independent: it takes its four 64-bit parameters
# from a literal pool appended right after the code. The QEMU loader
# (hw/arm/xnuboot_sptm.c) is responsible for:
#   1. copying the `CODE` bytes into a scratch code page in guest RAM, and
#   2. writing the four 8-byte pool words (ARRAY, ARRAY_END, STACKTOP, ENTRY)
#      into the pool that immediately follows the code.
#
# Nothing here is hardcoded to a physical address — the loader supplies all
# addresses at boot from the values it already computes (rx_phys, entrypoint).
#
# Requires: keystone-engine (present in vphone-cli/.venv). Run:
#   source /Users/maliosdark/vphone-cli/.venv/bin/activate && python3 gen_trampoline.py

from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
import struct, sys

# ---------------------------------------------------------------------------
# The trampoline. Register plan (AArch64 AAPCS):
#   The 11 constructors are ordinary AAPCS functions: each one saves/restores
#   x19..x28 and x29/x30, so x19..x24 SURVIVE across every `blr`. We keep all
#   loop state in those callee-saved registers.
#
#   x19 = saved x0 (SPTM handoff pointer, tag2)  — restored before entry
#   x20 = saved x1 (domain-descriptor pointer)   — restored before entry
#   x21 = cursor into __mod_init_func (advances by 8)
#   x22 = end of the __mod_init_func array (ARRAY + 11*8)
#   x23 = scratch: current constructor physical pointer
#
# Entry state (set by SPTM's ERET into CL4, then diverted here by the hook):
#   x0 = handoff, x1 = descriptor (may be injected), SP = 0, PSTATE = guarded EL1h.
# CL4's real entry (0x...691d4f0) REQUIRES SP==0 (it branches on `cmp sp,#0`),
# so we save the incoming SP==0 implicitly by re-zeroing SP before the final br.
#
# The constructors DO push to the stack, so we install a scratch stack
# (STACKTOP) before the loop and tear it down (SP=0) afterwards.
#
# PAC: the trampoline itself uses only `blr`/`br` and never signs/authenticates
# its own return address, so it needs no PAC key. Each constructor's internal
# pacibsp/retab pair is self-balanced against its own SP frame and round-trips
# exactly as it already does everywhere else CL4 currently runs.
# ---------------------------------------------------------------------------
ASM = r"""
    /* --- prologue: capture entry args, install scratch stack --- */
    mov   x19, x0            /* save SPTM handoff (tag2)            */
    mov   x20, x1            /* save domain descriptor (tag3)       */
    ldr   x21, Larray        /* x21 = &__mod_init_func[0] (phys)    */
    ldr   x22, Larray_end    /* x22 = &__mod_init_func[11]          */
    ldr   x9,  Lstacktop     /* x9  = top of scratch stack (phys)   */
    mov   sp,  x9            /* ctors need a real stack             */

    /* --- loop: call each constructor in array order --- */
Lloop:
    cmp   x21, x22
    b.hs  Ldone             /* cursor >= end -> finished           */
    ldr   x23, [x21], #8    /* x23 = *cursor ; cursor += 8         */
    blr   x23              /* call ctor (preserves x19..x22)      */
    b     Lloop

    /* --- epilogue: restore entry ABI and jump to real entry --- */
Ldone:
    mov   x0, x19           /* restore handoff                     */
    mov   x1, x20           /* restore descriptor                  */
    mov   x9, xzr
    mov   sp, x9           /* CL4 entry requires SP == 0          */
    ldr   x16, Lentry       /* x16 = real CL4 entry (phys)         */
    br    x16             /* tail-branch into CL4's entrypoint   */

    /* --- literal pool (filled in by the QEMU loader at boot) --- */
    .align 3
Larray:     .quad 0         /* rx_phys + 0x698fc0  (__mod_init_func) */
Larray_end: .quad 0         /* rx_phys + 0x698fc0 + 11*8            */
Lstacktop:  .quad 0         /* top of scratch stack, 16-byte aligned */
Lentry:     .quad 0         /* rx_phys + 0x994f0  (CL4 entrypoint)  */
"""

def main():
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoding, _ = ks.asm(ASM, addr=0)
    code = bytes(encoding)
    # The literal pool is the last 32 bytes (4 x .quad). Locate it.
    pool_size = 32
    code_size = len(code) - pool_size
    pool_off  = code_size
    assert len(code) % 8 == 0, "blob must be 8-byte aligned"

    # Sanity: the four pool words are currently zero.
    for i in range(4):
        w = struct.unpack_from("<Q", code, pool_off + i * 8)[0]
        assert w == 0, "pool word %d not zero (alignment padding shifted pool)" % i

    print("// CL4 __mod_init_func runner trampoline")
    print("// total %d bytes  (code %d + pool %d)" % (len(code), code_size, pool_size))
    print("// Pool words (loader must fill, in order):")
    print("//   [0] Larray     = rx_phys + 0x698fc0   at blob offset 0x%x" % (pool_off + 0))
    print("//   [1] Larray_end = rx_phys + 0x698fc0 + 88 at blob offset 0x%x" % (pool_off + 8))
    print("//   [2] Lstacktop  = scratch stack top      at blob offset 0x%x" % (pool_off + 16))
    print("//   [3] Lentry     = rx_phys + 0x994f0      at blob offset 0x%x" % (pool_off + 24))
    print()
    print("static const uint8_t cl4_ctor_trampoline[] = {")
    for i in range(0, len(code), 12):
        row = code[i:i+12]
        print("    " + " ".join("0x%02x," % b for b in row))
    print("};")
    print("#define CL4_TRAMP_POOL_OFF 0x%x  // offset of the 4-quad literal pool" % pool_off)
    print("#define CL4_TRAMP_SIZE     0x%x" % len(code))

    # Also emit a raw .bin next to this script for inspection / hexdump.
    with open("trampoline.bin", "wb") as f:
        f.write(code)
    # Emit an annotated disassembly-friendly listing constant too.
    with open("trampoline.hex", "w") as f:
        f.write("".join("%02x" % b for b in code) + "\n")

if __name__ == "__main__":
    main()
