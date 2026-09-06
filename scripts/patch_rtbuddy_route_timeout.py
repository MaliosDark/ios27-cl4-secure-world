#!/usr/bin/env python3
"""Make RTBuddy's route resolution non-blocking, unblocking DCP's start().

Root cause (established instruction-precisely by live kernel debugging,
FINDINGS Part 32-37): inside the route-resolution loop (0xa7c50bc),
RTBuddy(DCP)::start() calls, per route:

    mov x0, x28
    mov x1, #-1            ; timeout = UINT64_MAX = wait forever
    bl  <waitForMatchingService thunk>   [0xa7c5278 -> GOT 0x8386388]

For the DCP's secure-world route (SecureRTBuddyDCP / DCP-EXCLAVE), the matched
service never registers in this VM, so the wait blocks forever and start()
never returns -> RTBuddy(DCP) never registers -> no display.

This changes the timeout immediate from -1 (forever) to 0 (poll once, return
immediately). Present services are still found instantly; the absent secure
service returns null at once instead of hanging. The resulting null is carried
past the loop's error branch by patch_rtbuddy_route.py (the Part 24 NOP at
0xa7c52f0), which only becomes reachable once this hang is removed. The normal
mailbox route is untouched, so AppleDCP's later dereferences still find real
objects.

Anchored semantically: located inside the route loop (identified by its unique
"Finding route %d"/"Success route %d" string-load adds), the exact site is the
`mov x1, #-1` (movn x1,#0) that is immediately followed by a `bl` and preceded
by `mov x0, x28`. Replacement assembled by Keystone and verified by disassembly
before writing.
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
        cmd, cs = struct.unpack('<II', d[p:p+8]); yield p, cmd, cs; p += cs

def fileset_fileoff(d, name):
    for p, cmd, cs in macho_cmds(d, 0):
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff = struct.unpack('<QQ', d[p+8:p+24])
            if d[p+32:d.find(b'\0', p+32)] == name: return fileoff
    return None

def text_exec(d, fo):
    for p, cmd, cs in macho_cmds(d, fo):
        if cmd == LC_SEGMENT_64:
            if d[p+8:p+24].rstrip(b'\0') == b'__TEXT_EXEC':
                vmaddr, vmsize, foff, fsz = struct.unpack('<QQQQ', d[p+24:p+56])
                return vmaddr, foff
    return None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bootkc'); ap.add_argument('-n','--dry-run',action='store_true')
    args = ap.parse_args()
    d = bytearray(open(args.bootkc,'rb').read())

    fo = fileset_fileoff(d, b'com.apple.driver.RTBuddy')
    if fo is None: sys.exit("RTBuddy fileset not found")
    tx_va, tx_fo = text_exec(d, fo)
    if tx_va is None: sys.exit("RTBuddy __TEXT_EXEC not found")
    at = lambda va: tx_fo + (va - tx_va)

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    FIND_VA = 0xFFFFFFF00A7C5200   # add x3,x3,#0x3f4 -> "Finding route %d"
    SUCC_VA = 0xFFFFFFF00A7C538C   # add x3,x3,#0x412 -> "Success route %d"
    MOVX0_VA = 0xFFFFFFF00A7C5270  # mov x0, x28
    TMO_VA  = 0xFFFFFFF00A7C5274   # mov x1, #-1   (the timeout)
    BL_VA   = 0xFFFFFFF00A7C5278   # bl <waitForMatchingService thunk>

    if d[at(FIND_VA):at(FIND_VA)+4] != bytes([0x63,0xd0,0x0f,0x91]):
        sys.exit("anchor mismatch: 'Finding route' add")
    if d[at(SUCC_VA):at(SUCC_VA)+4] != bytes([0x63,0x48,0x10,0x91]):
        sys.exit("anchor mismatch: 'Success route' add")

    movx0 = next(md.disasm(bytes(d[at(MOVX0_VA):at(MOVX0_VA)+4]), MOVX0_VA), None)
    tmo   = next(md.disasm(bytes(d[at(TMO_VA):at(TMO_VA)+4]), TMO_VA), None)
    blin  = next(md.disasm(bytes(d[at(BL_VA):at(BL_VA)+4]), BL_VA), None)
    if not movx0 or movx0.mnemonic != 'mov' or movx0.op_str != 'x0, x28':
        sys.exit(f"anchor mismatch: expected 'mov x0, x28', got "
                 f"{movx0.mnemonic if movx0 else '??'} {movx0.op_str if movx0 else ''}")
    if not tmo or tmo.mnemonic != 'mov' or tmo.op_str != 'x1, #-1':
        sys.exit(f"anchor mismatch: expected 'mov x1, #-1', got "
                 f"{tmo.mnemonic if tmo else '??'} {tmo.op_str if tmo else ''}")
    if not blin or blin.mnemonic != 'bl':
        sys.exit(f"anchor mismatch: expected 'bl' after timeout, got "
                 f"{blin.mnemonic if blin else '??'}")

    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    new,_ = ks.asm("mov x1, #0", TMO_VA); new = bytes(new)
    chk = next(md.disasm(new, TMO_VA), None)
    if not chk or chk.mnemonic != 'mov' or chk.op_str != 'x1, #0':
        sys.exit("replacement verification failed")

    fo2 = at(TMO_VA)
    print(f"RTBuddy route wait timeout at file 0x{fo2:X}:")
    print(f"  {bytes(d[fo2:fo2+4]).hex()} (mov x1,#-1)  ->  {new.hex()} (mov x1,#0)")
    if not args.dry_run:
        d[fo2:fo2+4] = new; open(args.bootkc,'wb').write(d); print("patched")
    else:
        print("dry run, not written")

if __name__ == '__main__':
    main()
