"""Vendored ARM64 asm/disasm helpers (capstone + keystone) for the darwin-vm
patchers. Self-contained so this package does not depend on vphone-cli.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN as KS_MODE_LE

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True
_ks = Ks(KS_ARCH_ARM64, KS_MODE_LE)


def asm(s):
    enc, _ = _ks.asm(s)
    if not enc:
        raise RuntimeError(f"asm failed: {s}")
    return bytes(enc)


NOP = asm("nop")
RET = asm("ret")


def rd32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def wr32(data, off, val):
    struct.pack_into("<I", data, off, val)


def disasm_at(data, off, n=8):
    return list(_cs.disasm(bytes(data[off:off + n * 4]), off))


def _log_asm(data, offset, count=5, marker_off=-1):
    for insn in disasm_at(data, offset, count):
        tag = " >>>" if insn.address == marker_off else "    "
        print(f"  {tag} 0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
