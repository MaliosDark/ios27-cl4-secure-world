#!/usr/bin/env python3
# analyze_ctors.py — reproduce the CL4 __mod_init_func constructor analysis.
#
# Run:  source /Users/maliosdark/vphone-cli/.venv/bin/activate && python3 analyze_ctors.py
#
# Uses capstone against the extracted CL4 components:
#   __TEXT -> firmware/exclave_comp/txtk  (vmaddr base 0xc0000000)
#   __DATA -> firmware/exclave_comp/tadk  (vmaddr base 0xc068c000)
#
# Everything is derived from decode (mnemonic/operands) or raw-byte encoding
# scans — no hardcoded per-kernel symbol dumps.

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import struct, os

FW = "/Users/maliosdark/darwin-vm/firmware/exclave_comp"
TXT = open(os.path.join(FW, "txtk"), "rb").read()
TAD = open(os.path.join(FW, "tadk"), "rb").read()
BASE, DATA_VM = 0xc0000000, 0xc068c000
RX_PHYS = 0x10006884000  # CL4 __TEXT physical load base (RESUME UPDATE 5)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True


def read_vm(vm, n):
    if vm >= DATA_VM:
        o = vm - DATA_VM
        return TAD[o:o + n]
    o = vm - BASE
    return TXT[o:o + n]


def dis(vm, n=40, stop=True):
    for i in md.disasm(read_vm(vm, n * 4), vm):
        print("  0x%08x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
        if stop and i.mnemonic in ("ret", "retab", "retaa", "br", "braa", "brab"):
            break


def phys(vm):
    return RX_PHYS + (vm - BASE)


CTORS = [0xc0001800, 0xc00795d4, 0xc00a2ad4, 0xc00aa814, 0xc01552bc,
         0xc03c9868, 0xc04020e4, 0xc0402e98, 0xc0437ef0, 0xc0439524, 0xc043a8a4]


def modinit():
    print("== __mod_init_func @0xc0698fc0 (11 raw chained slots) ==")
    raw = read_vm(0xc0698fc0, 11 * 8)
    for i in range(11):
        p = struct.unpack_from("<Q", raw, i * 8)[0]
        # ptr_format 12 (ARM64E_USERLAND24) auth pointer: target = raw & 0xffffffff
        tgt = p & 0xffffffff
        vm = BASE + tgt
        print("  ctor[%2d] raw=0x%013x -> vmaddr 0x%08x  phys 0x%x"
              % (i, p, vm, phys(vm)))


def tpidr_scan():
    # linear capstone disasm desyncs; scan the fixed system-reg encodings.
    mrs, msr = [], []
    for off in range(0, len(TXT) - 3, 4):
        w = struct.unpack_from("<I", TXT, off)[0]
        if (w & 0xffffffe0) == 0xd53bd040:
            mrs.append(BASE + off)
        if (w & 0xffffffe0) == 0xd51bd040:
            msr.append(BASE + off)
    print("== tpidr_el0 access sites ==")
    print("  mrs (read):  %d sites" % len(mrs))
    print("  msr (write): %d sites -> %s"
          % (len(msr), ", ".join("0x%x" % a for a in msr)))
    inside = [a for a in mrs if any(c <= a < c + 0x400 for c in CTORS)]
    print("  mrs sites inside any ctor body (<0x400 window): %s"
          % (["0x%x" % a for a in inside] or "NONE"))


if __name__ == "__main__":
    modinit(); print()
    print("== ctor[0] 0xc0001800 (trivial: writes bool @0xc068e9a0) ==")
    dis(0xc0001800, 3); print("  -> tail target 0xc00a6cd4:"); dis(0xc00a6cd4, 4)
    print()
    print("== ctor[2] 0xc00a2ad4 REGISTRAR (seeds table 0xc068e840) ==")
    dis(0xc00a2ad4, 21)
    print()
    print("== register() 0xc00a2b28 (memcpy 0x50 into 0xc068e840+idx*0x50) ==")
    dis(0xc00a2b28, 24)
    print()
    print("== factory 0xc00a1e70 (TPIDR->[+0x10]->[0] linked-list lookup) ==")
    dis(0xc00a1e70, 17)
    print()
    print("== TPIDR setter 0xc00aa724 (msr tpidr_el0,x0 ; ret) ==")
    dis(0xc00aa724, 2)
    print()
    print("== CL4 entry 0xc00994f0 (phys 0x%x; requires SP==0) ==" % phys(0xc00994f0))
    dis(0xc00994f0, 20, stop=False)
    print()
    tpidr_scan()
