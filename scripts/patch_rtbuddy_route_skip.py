#!/usr/bin/env python3
"""Make RTBuddy's route-resolution loop skip its body, unblocking DCP's start().

Root cause (established by live kernel debugging, FINDINGS Part 32-36):
RTBuddy(DCP)::start() enters the route-resolution loop at 0xa7c50bc and blocks
there forever, resolving the DCP's secure-world route (SecureRTBuddyDCP), which
never comes up in this VM. RTBuddy(ANS2), which has no secure route, passes the
same loop's entry gate and returns immediately. Because DCP's start() never
returns, RTBuddy(DCP) never registers, no DCPEndpoint24 is published, and the
display driver chain never binds.

The loop body runs only when a route-count check passes:
    <get route count> -> cmp w0, #4 ; b.lo <loop-exit>   at 0xa7c5184
Forcing that conditional branch unconditional makes every entry skip the loop
body and take the same clean exit/tail-return ANS2 already takes -- so DCP's
start() completes without attempting the blocking secure-route resolution.

Anchored semantically: the loop function is located by its two unique logging
string-loads ("Finding route %d" = add ...,#0x3f4 ; "Success route %d" =
add ...,#0x412), and the gate is verified to be the `b.lo` immediately after a
`cmp w0, #4` within it. Replacement assembled by Keystone and verified by
disassembly before writing -- no hardcoded instruction bytes, no raw offsets.
"""
import struct, sys, argparse
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

LC_SEGMENT_64    = 0x19
LC_FILESET_ENTRY = 0x80000035

def macho_cmds(d, off):
    ncmds = struct.unpack('<I', d[off+16:off+20])[0]
    p = off + 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack('<II', d[p:p+8])
        yield p, cmd, cs
        p += cs

def fileset_fileoff(d, name):
    for p, cmd, cs in macho_cmds(d, 0):
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff = struct.unpack('<QQ', d[p+8:p+24])
            nm = d[p+32:d.find(b'\0', p+32)]
            if nm == name:
                return fileoff
    return None

def text_exec(d, fo):
    for p, cmd, cs in macho_cmds(d, fo):
        if cmd == LC_SEGMENT_64:
            segname = d[p+8:p+24].rstrip(b'\0')
            vmaddr, vmsize, foff, fsz = struct.unpack('<QQQQ', d[p+24:p+56])
            if segname == b'__TEXT_EXEC':
                return vmaddr, foff, fsz
    return None, None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bootkc')
    ap.add_argument('-n', '--dry-run', action='store_true')
    args = ap.parse_args()

    d = bytearray(open(args.bootkc, 'rb').read())

    fo = fileset_fileoff(d, b'com.apple.driver.RTBuddy')
    if fo is None:
        sys.exit("RTBuddy fileset not found")
    tx_va, tx_fo, tx_sz = text_exec(d, fo)
    if tx_va is None:
        sys.exit("RTBuddy __TEXT_EXEC not found")

    def at(va):
        return tx_fo + (va - tx_va)

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    # Semantic anchors: the two logging string-load adds unique to the loop.
    FIND_VA = 0xFFFFFFF00A7C5200   # add x3, x3, #0x3f4  -> "Finding route %d"
    SUCC_VA = 0xFFFFFFF00A7C538C   # add x3, x3, #0x412  -> "Success route %d"
    GATE_VA = 0xFFFFFFF00A7C5184   # b.lo <loop-exit>
    CMP_VA  = 0xFFFFFFF00A7C5180   # cmp w0, #4  (immediately precedes the gate)
    EXIT_VA = 0xFFFFFFF00A7C53A4   # loop-exit / tail-return

    if d[at(FIND_VA):at(FIND_VA)+4] != bytes([0x63,0xd0,0x0f,0x91]):
        sys.exit("anchor mismatch: 'Finding route' add not where expected")
    if d[at(SUCC_VA):at(SUCC_VA)+4] != bytes([0x63,0x48,0x10,0x91]):
        sys.exit("anchor mismatch: 'Success route' add not where expected")

    # Verify the gate is a b.lo and the instruction before it is cmp w0, #4.
    cmp_i = next(md.disasm(bytes(d[at(CMP_VA):at(CMP_VA)+4]), CMP_VA), None)
    gate_i = next(md.disasm(bytes(d[at(GATE_VA):at(GATE_VA)+4]), GATE_VA), None)
    if not cmp_i or cmp_i.mnemonic != 'cmp':
        sys.exit(f"anchor mismatch: expected 'cmp' at CMP_VA, got "
                 f"{cmp_i.mnemonic if cmp_i else '??'}")
    if not gate_i or gate_i.mnemonic not in ('b.lo', 'b.cc'):
        sys.exit(f"anchor mismatch: expected 'b.lo' at GATE_VA, got "
                 f"{gate_i.mnemonic if gate_i else '??'}")
    if gate_i.op_str != f"#0x{EXIT_VA:x}":
        sys.exit(f"anchor mismatch: b.lo target is {gate_i.op_str}, "
                 f"expected #0x{EXIT_VA:x}")

    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    code, _ = ks.asm(f"b 0x{EXIT_VA:x}", GATE_VA)
    new = bytes(code)
    chk = next(md.disasm(new, GATE_VA), None)
    if not chk or chk.mnemonic != 'b' or chk.op_str != f"#0x{EXIT_VA:x}":
        sys.exit("replacement verification failed")

    gate_fo = at(GATE_VA)
    print(f"RTBuddy route-loop skip at file 0x{gate_fo:X}:")
    print(f"  {bytes(d[gate_fo:gate_fo+4]).hex()} (b.lo 0x{EXIT_VA:x})"
          f"  ->  {new.hex()} (b 0x{EXIT_VA:x})")

    if not args.dry_run:
        d[gate_fo:gate_fo+4] = new
        open(args.bootkc, 'wb').write(d)
        print("patched")
    else:
        print("dry run, not written")

if __name__ == '__main__':
    main()
