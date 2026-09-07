"""Read-only anchor verification for the darwin-vm cryptex/SSV patch chain.

Resolves every DVM-1..DVM-5 anchor against a kernelcache and reports the
candidate site (string VA, xref VA, function/gate VA) plus a short disassembly,
WITHOUT writing anything. Use this to compare against section 3 of
research/kernel_patch_jb/patch_darwinvm_cryptex_boot.md before running the
actual patchers.

Usage:
    python3 -m scripts.patchers.darwinvm_verify_anchors <kernelcache>

Exit code 0 if every anchor resolves, 1 otherwise.
"""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from .darwinvm_patch_img4_magazine import (
    _parse_fileset_entry,
    _parse_kext_segments,
    _find_string_in_section,
    _find_adrp_add_xref,
    _walk_back_to_prologue,
    PACIBSP,
)
from .darwinvm_patch_ssv import _seg_containing_str, _find_branch_into

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True


def _disasm_va(data, fileoff, base_va, seg_fileoff, n=6):
    """Disassemble n insns at fileoff, labelling addresses with their VA."""
    lines = []
    chunk = bytes(data[fileoff : fileoff + n * 4])
    for insn in _cs.disasm(chunk, base_va + (fileoff - seg_fileoff)):
        lines.append(f"      0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}")
    return lines


def _resolve_kext_string_func(data, kext_name, needle, want_prologue=True):
    """Resolve a string->xref->(function|gate) in a kext. Returns a dict report."""
    r = {"kext": kext_name, "needle": needle, "ok": False}
    entry = _parse_fileset_entry(data, kext_name)
    if not entry:
        r["error"] = f"{kext_name} not found"
        return r
    kext_fileoff, _ = entry
    segs = _parse_kext_segments(data, kext_fileoff)
    text = segs.get("__TEXT")
    exc = segs.get("__TEXT_EXEC")
    if not text or not exc:
        r["error"] = "missing __TEXT/__TEXT_EXEC"
        return r
    tv, tvs, tf, tfs = text
    ev, evs, ef, efs = exc

    str_foff = _find_string_in_section(data, tf, tfs, needle.encode())
    if str_foff < 0:
        r["error"] = "string not found"
        return r
    r["str_va"] = tv + (str_foff - tf)

    xref = _find_adrp_add_xref(data, ev, ef, efs, r["str_va"])
    if xref < 0:
        r["error"] = "no ADRP+ADD xref"
        return r
    r["xref_va"] = ev + (xref - ef)
    r["xref_foff"] = xref

    if want_prologue:
        func = _walk_back_to_prologue(data, xref)
        if func < 0:
            r["error"] = "no prologue"
            return r
        r["func_va"] = ev + (func - ef)
        r["func_foff"] = func
        first = struct.unpack_from("<I", data, func)[0]
        r["prologue"] = "PACIBSP" if first == PACIBSP else f"0x{first:08X}"
        r["disasm"] = _disasm_va(data, func, ev, ef)
    else:
        # Report nearest preceding conditional gate.
        gate = -1
        for back in range(1, 13):
            foff = xref - back * 4
            insns = list(_cs.disasm(bytes(data[foff : foff + 4]), 0))
            if insns and insns[0].mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
                gate = foff
                break
        if gate < 0:
            r["error"] = "no conditional gate near xref"
            return r
        r["gate_va"] = ev + (gate - ef)
        r["gate_foff"] = gate
        r["disasm"] = _disasm_va(data, gate - 8, ev, ef)

    r["ok"] = True
    return r


def _print_report(title, r):
    print(f"\n[{'OK ' if r['ok'] else 'MISS'}] {title}")
    print(f"      kext   : {r.get('kext')}")
    print(f"      string : {r['needle']!r}")
    if "str_va" in r:
        print(f"      str_va : 0x{r['str_va']:X}")
    if "xref_va" in r:
        print(f"      xref   : 0x{r['xref_va']:X}")
    if "func_va" in r:
        print(f"      func   : 0x{r['func_va']:X} (prologue {r.get('prologue')})")
    if "gate_va" in r:
        print(f"      gate   : 0x{r['gate_va']:X}")
    if "disasm" in r:
        print("      disasm :")
        for line in r["disasm"]:
            print(line)
    if not r["ok"]:
        print(f"      reason : {r.get('error')}")


def verify(filepath):
    data = bytearray(open(filepath, "rb").read())
    print(f"[verify] {filepath}  ({len(data)} bytes)")

    reports = []

    # DVM-1: AppleImage4 magazine/nonce functions (stubs)
    for needle, label in [
        ("failed to read nonce slot data", "DVM-1 nonce_slot_read"),
        ("failed to entangle nonce", "DVM-1 nonce_entangle"),
        ("failed to get nonce:", "DVM-1 nonce_get"),
        ("demand magazine i/o failed", "DVM-1 magazine_io"),
        ("failed to set supervisor nonce", "DVM-1 nonce_set_supervisor"),
        ("failed to roll supervisor nonce", "DVM-1 nonce_roll_supervisor"),
        ("failed to write slot after rolling", "DVM-1 nonce_write_slot"),
    ]:
        r = _resolve_kext_string_func(
            data, "com.apple.security.AppleImage4", needle, want_prologue=True)
        _print_report(label, r)
        reports.append((label, r))

    # DVM-2: Image4 asmb setup (gate NOP)
    r = _resolve_kext_string_func(
        data, "com.apple.security.Image4",
        "unable to setup /chosen/asmb node", want_prologue=False)
    _print_report("DVM-2 image4_asmb_setup", r)
    reports.append(("DVM-2 image4_asmb_setup", r))

    # DVM-3: apfs seal_is_broken (stub)
    r = _resolve_kext_string_func(
        data, "com.apple.filesystems.apfs",
        "authapfs_seal_is_broken", want_prologue=True)
    _print_report("DVM-3 apfs_seal_is_broken", r)
    reports.append(("DVM-3 apfs_seal_is_broken", r))

    # DVM-4: root-hash auth predicate (stub -> return 0 = "not required")
    r4 = None
    for needle in ("is_root_hash_authentication_required_ios",
                   "is_root_hash_authentication_required"):
        r = _resolve_kext_string_func(
            data, "com.apple.filesystems.apfs", needle, want_prologue=True)
        if r["ok"]:
            r4 = r
            break
        r4 = r
    _print_report("DVM-4 root_hash_auth_required", r4)
    reports.append(("DVM-4 root_hash_auth_required", r4))

    # DVM-5: bsd_init root-auth (kernel __TEXT_EXEC gate NOP)
    r5 = {"kext": "kernel", "needle": "rootvp not authenticated after mounting", "ok": False}
    str_foff, str_va = _seg_containing_str(data, r5["needle"])
    if str_foff >= 0:
        r5["str_va"] = str_va
        # Locate kernel __TEXT_EXEC
        ncmds = struct.unpack_from("<I", data, 16)[0]
        off = 32
        ev = ef = efs = -1
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == 0x19:
                segname = data[off + 8 : off + 24].split(b"\0")[0].decode(errors="replace")
                if segname == "__TEXT_EXEC":
                    ev = struct.unpack_from("<Q", data, off + 24)[0]
                    ef = struct.unpack_from("<Q", data, off + 40)[0]
                    efs = struct.unpack_from("<Q", data, off + 48)[0]
                    break
            off += cmdsize
        if ev >= 0:
            xref = _find_adrp_add_xref(data, ev, ef, efs, str_va)
            if xref >= 0:
                r5["xref_va"] = ev + (xref - ef)
                gate = _find_branch_into(data, xref, ev, ef)
                if gate >= 0:
                    r5["gate_va"] = ev + (gate - ef)
                    r5["disasm"] = _disasm_va(data, gate - 8, ev, ef)
                    r5["ok"] = True
                else:
                    r5["error"] = "no gate branches into panic block"
                    # Diagnostic: dump the region around the panic-block xref so
                    # the true guard branch (and its direction) can be read off.
                    print("\n      [diag] context around bsd_init panic xref:")
                    for line in _disasm_va(data, xref - 0x40, ev, ef, n=24):
                        print(line)
                    print("      [diag] conditional branches within -0x400:")
                    for back in range(1, 256):
                        foff = xref - back * 4
                        if foff < ef:
                            break
                        va = ev + (foff - ef)
                        insns = list(_cs.disasm(bytes(data[foff:foff + 4]), va))
                        if insns and insns[0].mnemonic in (
                                "cbz", "cbnz", "tbz", "tbnz") or (
                                insns and insns[0].mnemonic.startswith("b.")):
                            ins = insns[0]
                            tgt = (ins.operands[-1].imm & 0xFFFFFFFFFFFFFFFF) if ins.operands else 0
                            print(f"        0x{va:X}: {ins.mnemonic} {ins.op_str}  -> target 0x{tgt:X}")
            else:
                r5["error"] = "no xref to panic string"
        else:
            r5["error"] = "kernel __TEXT_EXEC not found"
    else:
        r5["error"] = "panic string not found"
    _print_report("DVM-5 bsd_init_rootauth", r5)
    reports.append(("DVM-5 bsd_init_rootauth", r5))

    ok = sum(1 for _, r in reports if r["ok"])
    print(f"\n[verify] {ok}/{len(reports)} anchors resolved")
    for label, r in reports:
        print(f"    {'[+]' if r['ok'] else '[-]'} {label}")
    return ok == len(reports)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <kernelcache>")
        sys.exit(2)
    sys.exit(0 if verify(sys.argv[1]) else 1)


if __name__ == "__main__":
    main()
