"""darwin-vm SSV / root-auth bypass for booting a non-sealed root volume.

Companion to darwinvm_patch_img4_magazine. Where the img4 module makes the
cryptex validate without SEP, this module lets the kernel continue past the
signed-system-volume (SSV) authentication gates when the mounted root is a
plain (non-sealed) APFS volume, as produced by inject_cryptex.sh.

Targets (all in an MH_FILESET iOS kernelcache, base VA 0xfffffff007004000):

  1. com.apple.security.Image4 : /chosen/asmb setup
       When the device tree has no /chosen/asmb (darwin-vm boots XNU directly,
       so iBoot never created it), the Image4 kext logs
       "unable to setup /chosen/asmb node" and takes its failure branch. This
       NOPs the bail branch so init continues.

  2. apfs : authapfs_seal_is_broken
       Force "seal not broken" so a non-sealed volume is treated as intact.

  3. apfs : apfs_vfsop_mount root-auth
       The "Need authenticator (81)" path that rejects a root volume with no
       authenticator. Stubbed so mount proceeds.

  4. kernel : bsd_init root authentication
       Follows the sanctioned reveal flow (see CLAUDE.md): recover bsd_init via
       the "rootvp not authenticated after mounting" panic string xref, find the
       in-function conditional branch guarding the panic, and NOP only that gate.

Every patch prints its before/after disassembly and gates on an expected
instruction shape. Because execution against real firmware is done by the
operator, VERIFY the printed before/after against the target kernelcache
before booting a patched image.

Usage:
    python3 -m scripts.patchers.darwinvm_patch_ssv <kernelcache> [--dry-run]
"""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from ._asm import asm, disasm_at, _log_asm
from .darwinvm_patch_img4_magazine import (
    _parse_fileset_entry,
    _parse_kext_segments,
    _find_string_in_section,
    _find_adrp_add_xref,
    _walk_back_to_prologue,
    _stub_function,
    PACIBSP,
)

_cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs.detail = True

NOP32 = struct.unpack("<I", asm("nop"))[0]


def _seg_containing_str(data, needle):
    """Locate a C string across the whole kernelcache __TEXT.

    Returns (str_fileoff, str_vmaddr) using the top-level __TEXT segment map,
    or (-1, -1). Used for kernel-proper (non-kext) anchors.
    """
    # Top-level (kernelcache) __TEXT
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            segname = data[off + 8 : off + 24].split(b"\0")[0].decode(errors="replace")
            vmaddr = struct.unpack_from("<Q", data, off + 24)[0]
            vmsize = struct.unpack_from("<Q", data, off + 32)[0]
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            filesize = struct.unpack_from("<Q", data, off + 48)[0]
            if segname in ("__TEXT", "__PRELINK_TEXT"):
                idx = data.find(needle.encode(), fileoff, fileoff + filesize)
                if idx >= 0:
                    return idx, vmaddr + (idx - fileoff)
        off += cmdsize
    return -1, -1


def _find_branch_into(data, xref_foff, seg_vmaddr, seg_fileoff,
                       window_back=1200, block_span=0x80):
    """Find a conditional branch that jumps INTO the block around xref.

    Used for panic blocks: the panic-string load (xref) sits inside a block
    that a guard branch elsewhere jumps to on failure. Scans backward from the
    xref for cbz/cbnz/tbz/tbnz whose decoded target lands in
    [xref - block_span, xref + 4]. Returns the branch file offset, or -1.

    Disassembles with the instruction's VA as address so the operand target is
    a real VA; compares in VA space, returns a file offset.
    """
    xref_va = seg_vmaddr + (xref_foff - seg_fileoff)
    lo = xref_va - block_span
    hi = xref_va + 4
    br = {"cbz", "cbnz", "tbz", "tbnz"}
    for back in range(1, window_back):
        foff = xref_foff - back * 4
        if foff < seg_fileoff:
            break
        va = seg_vmaddr + (foff - seg_fileoff)
        insns = list(_cs.disasm(bytes(data[foff : foff + 4]), va))
        if not insns:
            continue
        ins = insns[0]
        if ins.mnemonic in br and ins.operands:
            # capstone returns the branch target signed; mask to unsigned 64-bit
            # (high-half kernel VAs otherwise come back negative and never match).
            target = ins.operands[-1].imm & 0xFFFFFFFFFFFFFFFF
            if lo <= target <= hi:
                return foff
    return -1


def _find_cond_branch_after(data, start_foff, base_va, foff_to_va_delta,
                             max_insns=24):
    """Find the first conditional branch (cbz/cbnz/tbz/tbnz/b.cc) after start.

    Returns file offset of the branch, or -1.
    """
    br = {"cbz", "cbnz", "tbz", "tbnz"}
    for i in range(max_insns):
        foff = start_foff + i * 4
        insns = disasm_at(data, foff, 1)
        if not insns:
            continue
        m = insns[0].mnemonic
        if m in br or (m.startswith("b.") and m != "b."):
            return foff
    return -1


# ── 1. Image4 kext: /chosen/asmb setup ─────────────────────────────

def patch_image4_asmb_setup(data, dry_run=False):
    """NOP the failure branch when /chosen/asmb is absent.

    In com.apple.security.Image4, the setup routine logs
    "unable to setup /chosen/asmb node" then branches to bail. We locate the
    string xref and NOP the conditional branch immediately preceding the log
    (the gate that decides to take the failure path).
    """
    print("\n--- image4_asmb_setup ---")
    entry = _parse_fileset_entry(data, "com.apple.security.Image4")
    if not entry:
        print("  [-] com.apple.security.Image4 not found")
        return False
    kext_fileoff, _ = entry
    segs = _parse_kext_segments(data, kext_fileoff)

    text = segs.get("__TEXT")
    exc = segs.get("__TEXT_EXEC")
    if not text or not exc:
        print("  [-] missing segments")
        return False

    tv, tvs, tf, tfs = text
    ev, evs, ef, efs = exc

    needle = b"unable to setup /chosen/asmb node"
    str_foff = _find_string_in_section(data, tf, tfs, needle)
    if str_foff < 0:
        print("  [-] asmb string not found")
        return False
    str_va = tv + (str_foff - tf)
    print(f"  string at VA 0x{str_va:X}")

    xref = _find_adrp_add_xref(data, ev, ef, efs, str_va)
    if xref < 0:
        print("  [-] no xref to asmb string")
        return False
    xref_va = ev + (xref - ef)
    print(f"  xref at VA 0x{xref_va:X}")

    # The bail decision is a conditional branch shortly BEFORE the log call.
    # Scan backwards up to 12 insns for a cbz/cbnz that jumps forward to the
    # log/return block. Patch only that branch.
    for back in range(1, 13):
        foff = xref - back * 4
        insns = disasm_at(data, foff, 1)
        if not insns:
            continue
        m = insns[0].mnemonic
        if m in ("cbz", "cbnz", "tbz", "tbnz"):
            print("  Before:")
            _log_asm(data, foff - 8, 5, foff)
            if not dry_run:
                struct.pack_into("<I", data, foff, NOP32)
            print("  After:")
            _log_asm(data, foff - 8, 5, foff)
            print(f"  [+] NOPped asmb bail gate at VA 0x{ev + (foff - ef):X}")
            return True

    print("  [!] no conditional gate found near xref; manual review needed")
    return False


# ── 2 & 3. apfs SSV gates ──────────────────────────────────────────

def _patch_apfs_func_return(data, needle, name, retval=0, dry_run=False):
    """Find an apfs function by error-string xref and stub it to return retval."""
    print(f"\n--- {name} ---")
    entry = _parse_fileset_entry(data, "com.apple.filesystems.apfs")
    if not entry:
        print("  [-] apfs kext not found")
        return False
    kext_fileoff, _ = entry
    segs = _parse_kext_segments(data, kext_fileoff)
    text = segs.get("__TEXT")
    exc = segs.get("__TEXT_EXEC")
    if not text or not exc:
        print("  [-] missing segments")
        return False
    tv, tvs, tf, tfs = text
    ev, evs, ef, efs = exc

    str_foff = _find_string_in_section(data, tf, tfs, needle.encode())
    if str_foff < 0:
        print(f"  [-] string not found: {needle!r}")
        return False
    str_va = tv + (str_foff - tf)
    xref = _find_adrp_add_xref(data, ev, ef, efs, str_va)
    if xref < 0:
        print("  [-] no xref")
        return False
    func = _walk_back_to_prologue(data, xref)
    if func < 0:
        print("  [-] no prologue")
        return False
    print(f"  function at VA 0x{ev + (func - ef):X}")
    if dry_run:
        print("  Would stub:")
        _log_asm(data, func, 4, func)
        return True
    return _stub_function(data, func, name)


def patch_apfs_seal_is_broken(data, dry_run=False):
    """Force authapfs_seal_is_broken -> 0 (seal intact)."""
    return _patch_apfs_func_return(
        data, "authapfs_seal_is_broken", "apfs_seal_is_broken",
        retval=0, dry_run=dry_run)


def patch_apfs_vfsop_mount_auth(data, dry_run=False):
    """Force root-hash authentication to be "not required".

    The SSV root-auth gate that produces "apfs_vfsop_mount: Need authenticator
    (81)" is governed by the predicate `is_root_hash_authentication_required`
    (and its iOS variant). Each function loads its own name as a %s log arg, so
    an ADRP+ADD xref to that string sits inside the function; we resolve it,
    walk back to the prologue, and stub the whole predicate to return 0
    ("not required"). This is the established SSV bypass and is cleaner than
    NOPping a branch near an unrelated string.
    """
    print("\n--- apfs_vfsop_mount_auth (root-hash auth not required) ---")
    # Prefer the iOS variant; fall back to the generic one.
    for needle, label in (
        ("is_root_hash_authentication_required_ios", "root_hash_auth_req_ios"),
        ("is_root_hash_authentication_required", "root_hash_auth_req"),
    ):
        if _patch_apfs_func_return(data, needle, label, retval=0, dry_run=dry_run):
            return True
    print("  [-] no root-hash-auth predicate resolved")
    return False


# ── 4. bsd_init root authentication (sanctioned reveal flow) ────────

def patch_bsd_init_rootauth(data, dry_run=False):
    """Patch only the bsd_init rootvp-auth branch gate.

    Reveal flow (CLAUDE.md): recover bsd_init via the panic string
    "rootvp not authenticated after mounting", find its xref, walk back to the
    unique in-function conditional branch guarding the panic, and NOP it.
    """
    print("\n--- bsd_init_rootauth ---")
    needle = "rootvp not authenticated after mounting"
    str_foff, str_va = _seg_containing_str(data, needle)
    if str_foff < 0:
        print("  [-] panic string not found")
        return False
    print(f"  panic string at VA 0x{str_va:X}")

    # Find the xref to the panic string in the main kernel __TEXT_EXEC.
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    ev = ef = efs = -1
    while ncmds > 0:
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            segname = data[off + 8 : off + 24].split(b"\0")[0].decode(errors="replace")
            if segname == "__TEXT_EXEC":
                ev = struct.unpack_from("<Q", data, off + 24)[0]
                ef = struct.unpack_from("<Q", data, off + 40)[0]
                efs = struct.unpack_from("<Q", data, off + 48)[0]
                break
        off += cmdsize
        ncmds -= 1

    if ev < 0:
        print("  [-] kernel __TEXT_EXEC not found")
        return False

    xref = _find_adrp_add_xref(data, ev, ef, efs, str_va)
    if xref < 0:
        print("  [-] no xref to panic string")
        return False
    xref_va = ev + (xref - ef)
    print(f"  panic xref at VA 0x{xref_va:X}")

    # The panic-string xref sits INSIDE the panic block. The auth gate is a
    # conditional branch elsewhere that jumps INTO that block on failure
    # (e.g. `cbnz w0, <panic_block>` right after the FSIOC_KERNEL_ROOTAUTH
    # ioctl). So find the branch whose TARGET lands in the panic block
    # (a small window at/just before the xref), not a branch before the xref.
    gate = _find_branch_into(data, xref, ev, ef)
    if gate < 0:
        print("  [!] no gate found; manual review needed")
        return False

    print("  Before:")
    _log_asm(data, gate - 8, 5, gate)
    if not dry_run:
        struct.pack_into("<I", data, gate, NOP32)
    print("  After:")
    _log_asm(data, gate - 8, 5, gate)
    print(f"  [+] NOPped bsd_init root-auth gate at VA 0x{ev + (gate - ef):X}")
    return True


def patch_ssv_bypass(filepath, dry_run=False, with_asmb=False):
    data = bytearray(open(filepath, "rb").read())
    print(f"[ssv] Loaded {len(data)} bytes from {filepath}")

    results = {
        "apfs_seal_is_broken": patch_apfs_seal_is_broken(data, dry_run),
        "apfs_vfsop_mount_auth": patch_apfs_vfsop_mount_auth(data, dry_run),
        "bsd_init_rootauth": patch_bsd_init_rootauth(data, dry_run),
    }

    # DVM-2 (image4_asmb_setup) is OFF by default. Forcing the asmb "success"
    # path calls into PPL asmb processing that panics with
    #   "Image4: attempted to get expert without PPL context" @PPL.c:397
    # because darwin-vm has no PPL asmb context. The natural (unpatched) path
    # just logs "unable to setup /chosen/asmb node" and continues, which is what
    # we want. Enable only for experiments via --with-asmb.
    if with_asmb:
        results["image4_asmb_setup"] = patch_image4_asmb_setup(data, dry_run)

    applied = sum(1 for v in results.values() if v)
    print(f"\n[ssv] {applied}/{len(results)} patches resolved")
    for name, ok in results.items():
        print(f"    {'[+]' if ok else '[-]'} {name}")

    if applied and not dry_run:
        open(filepath, "wb").write(data)
        print(f"[ssv] Wrote {filepath}")
    elif dry_run:
        print("[ssv] dry-run: no file written")

    return applied > 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    with_asmb = "--with-asmb" in sys.argv
    if not args:
        print(f"Usage: {sys.argv[0]} <kernelcache> [--dry-run] [--with-asmb]")
        sys.exit(1)
    ok = patch_ssv_bypass(args[0], dry_run=dry, with_asmb=with_asmb)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
