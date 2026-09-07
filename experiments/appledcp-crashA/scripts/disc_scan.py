#!/usr/bin/env python3
"""Find all uses of a PAC discriminator immediate (default 0xba5) across
__TEXT_EXEC, classify following insn as SIGN (paci*/pacd*) / CALL (blraa/braa)
/ AUTH. Resyncing decode (4-byte step on desync). Usage: disc_scan.py [disc]"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM
KC="/Users/maliosdark/darwin-vm/firmware/bootkc"; D=open(KC,"rb").read()
ncmds,=struct.unpack("<I",D[16:20]); off=32; SEGS=[]
for _ in range(ncmds):
    cmd,cs=struct.unpack("<II",D[off:off+8])
    if cmd==0x19:
        n=D[off+8:off+24].split(b"\0")[0].decode()
        vm,vs,fo,fs=struct.unpack("<QQQQ",D[off+24:off+56]); SEGS.append((n,vm,vs,fo,fs))
    off+=cs
def v2f(v):
    for n,vm,vs,fo,fs in SEGS:
        if vm<=v<vm+vs and v-vm<fs: return fo+(v-vm)
    return None
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
te=[s for s in SEGS if s[0]=="__TEXT_EXEC"][0]
disc=int(sys.argv[1],0) if len(sys.argv)>1 else 0xba5
lo=te[1]; hi=te[1]+te[4]
allins=[]
a=lo
fo0=v2f(lo)
blk=D[fo0:fo0+(hi-lo)]
# resync loop over the single contiguous blob
pos=0
while pos < len(blk):
    got=False
    for ins in md.disasm(blk[pos:pos+4096], lo+pos):
        allins.append(ins); got=True
    # jump to after last decoded
    if got:
        pos = (allins[-1].address - lo) + 4
    else:
        pos += 4
idx={ins.address:i for i,ins in enumerate(allins)}
hits=0
for i,ins in enumerate(allins):
    m=ins.mnemonic; ops=ins.operands
    if m in("mov","movz","orr") and len(ops)>=2 and ops[0].type==ARM64_OP_REG and ops[-1].type==ARM64_OP_IMM and ops[-1].imm==disc:
        reg=ops[0].reg
        for j in range(i+1,min(i+8,len(allins))):
            n2=allins[j]; mm=n2.mnemonic
            if mm.startswith("paci") or mm.startswith("pacd") or mm in("blraa","braa","blrab","brab") or mm.startswith("auti") or mm.startswith("autd"):
                kind="SIGN" if (mm.startswith("paci") or mm.startswith("pacd")) else ("AUTH" if mm.startswith("aut") else "CALL")
                print(f"{ins.address:#011x} fo={v2f(ins.address):#09x} [{kind}] {mm:7} {n2.op_str}")
                hits+=1; break
print(f"# total {hits}", file=sys.stderr)
