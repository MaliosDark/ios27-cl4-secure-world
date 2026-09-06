#!/usr/bin/env python3
# Bounded call-graph reachability within CL4 __TEXT using clean edges:
# - 'bl #imm' -> call edge
# - terminal unconditional 'b #imm' to outside [entry, cur] -> tail-call edge (then stop)
# - conditional b.cc and local b are IGNORED (local control flow)
import capstone, sys, collections
TXTK="/Users/maliosdark/darwin-vm/firmware/exclave_comp/txtk"; VMBASE=0xc0000000
TEXT_LO=0xc0001200; TEXT_HI=0xc04ea8e8
data=open(TXTK,'rb').read()
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
_cache={}
def callees(entry, maxins=6000):
    if entry in _cache: return _cache[entry]
    outs=[]; off=entry-VMBASE; n=0; start=entry
    while n<maxins and 0<=off<len(data)-4:
        va=VMBASE+off
        try: insn=next(md.disasm(data[off:off+4],va,count=1))
        except StopIteration: break
        m=insn.mnemonic; ops=insn.op_str
        if m in ("ret","retab","reta"): break
        if m in ("br","braa","brab","brk") and False: pass
        if m=="bl" and ops.startswith("#"):
            t=int(ops[1:],0)
            if TEXT_LO<=t<TEXT_HI: outs.append(t)
        elif m=="b" and ops.startswith("#"):
            t=int(ops[1:],0)
            if t< start or t> va:   # branch outside function body => tail call
                if TEXT_LO<=t<TEXT_HI: outs.append(t)
                break
            # else local backward/forward branch: ignore, keep scanning
        off+=4; n+=1
    _cache[entry]=outs
    return outs
def reachable(start, targets, maxnodes=400000):
    parent={start:None}; q=collections.deque([start])
    while q:
        f=q.popleft()
        for c in callees(f):
            if c not in parent:
                parent[c]=f; q.append(c)
        if len(parent)>maxnodes: break
    def path(t):
        p=[]; x=t
        while x is not None: p.append(x); x=parent.get(x)
        return list(reversed(p))
    return {t:(path(t) if t in parent else None) for t in targets}, len(parent)
if __name__=="__main__":
    start=int(sys.argv[1],0); targets=[int(x,0) for x in sys.argv[2:]]
    res,nn=reachable(start,targets)
    print("(explored %d nodes)"%nn)
    for t,p in res.items():
        if p is None: print("0x%x : NOT reachable from 0x%x"%(t,start))
        else: print("0x%x : reachable depth %d : %s"%(t,len(p)," -> ".join("0x%x"%a for a in p[:30])))
