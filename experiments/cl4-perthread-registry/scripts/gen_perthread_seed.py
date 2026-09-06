#!/usr/bin/env python3
# gen_perthread_seed.py -- emit the exact per-thread registry seed for the
# FALLBACK fix (option b): pre-populate the synthesized fake per-thread context's
# singly-linked list so factory 0xc00a1e70 finds the base-service nodes.
#
# Node ABI (verified from factory 0xc00a1e70 + register 0xc00a1e20 + static
# templates 0xc068d6xx):
#     +0x00  next   (u64)  -> next node, 0 = end of list
#     +0x08  key1   (u32)  -> factory arg x0 ; upper 32 bits ignored
#     +0x10  key2   (u32)  -> factory arg x1 ; upper 32 bits ignored
#     +0x18  value  (u64)  -> returned object pointer
# List head = [ [tpidr_el0 + 0x10] + 0x00 ].  register() CAS-pushes at the head,
# so order within the list does not matter for lookup.
#
# Physical addressing: everything CL4 touches MMU-off runs at
#     phys(vmaddr) = 0x10006884000 + (vmaddr - 0xc0000000)
# so the (2,5) value object 0xc06fece8 lives at phys 0x10006f82ce8.
#
# The loader builds the fake context in the CL4-dummypage scratch (UPDATE 14):
#     g_cl4_tpidr = dummypage_phys + 0x200      (fake per-thread ctx base)
# We reserve a registry sub-area at ctx+0x400 and lay the nodes after it.

RX_PHYS = 0x10006884000
BASE = 0xc0000000
def phys(vm): return RX_PHYS + (vm - BASE)

CTX_OFF   = 0x200          # fake ctx base within dummypage (g_cl4_tpidr)
REGOBJ_OFF= 0x400          # regobj cell:  [ctx+0x10] -> ctx+0x400 ; [ctx+0x400] = head
NODES_OFF = 0x420          # first node
NODE_SZ   = 0x20

# The base services CL4's domain-setup (0xc00982e0 @0xc00a7178) would register.
# key1/key2 from the static templates; value from the register call sites.
#   (2,5) value = 0xc06fece8              (hardcoded at 0xc0098334)  <-- the fault
#   (2,4) value = dynamic ([handoff+0x10]); use 0 (scratch) unless known
#   others left out of the minimal seed.
NODES = [
    # (key1, key2, value_vmaddr_or_None, note)
    (2, 5, 0xc06fece8, "singleton object; accessor 0xc0098ce0 reads [+0x2a0]"),
]

def build(dummypage_phys):
    ctx = dummypage_phys + CTX_OFF
    regobj = dummypage_phys + REGOBJ_OFF
    print("# dummypage_phys = 0x%x  (loader-supplied at boot)" % dummypage_phys)
    print("# g_cl4_tpidr    = ctx = 0x%x" % ctx)
    print("# [ctx+0x10] (regobj ptr) = 0x%x" % regobj)
    print("# [regobj+0]  (list head) = 0x%x  (first node)" % (dummypage_phys + NODES_OFF))
    head = 0
    # build from tail so `next` links form a chain; head ends as first node addr
    addr = dummypage_phys + NODES_OFF
    laid = []
    for i, (k1, k2, val_vm, note) in enumerate(NODES):
        node = dummypage_phys + NODES_OFF + i * NODE_SZ
        nxt = dummypage_phys + NODES_OFF + (i + 1) * NODE_SZ if i + 1 < len(NODES) else 0
        val = phys(val_vm) if val_vm is not None else 0
        laid.append((node, nxt, k1, k2, val, note))
    for node, nxt, k1, k2, val, note in laid:
        print("\nnode @0x%x   # (%d,%d) %s" % (node, k1, k2, note))
        print("  +0x00 next  = 0x%x" % nxt)
        print("  +0x08 key1  = %d" % k1)
        print("  +0x10 key2  = %d" % k2)
        print("  +0x18 value = 0x%x  (phys of vmaddr 0x%x)" % (val, NODES[0][2]))
    print("\n# writes the loader must perform (pseudo-C, dummypage is the scratch VA):")
    print("  *(uint64_t*)(dummypage + 0x%x) = dummypage_phys + 0x%x;  // [ctx+0x10]=regobj" % (CTX_OFF+0x10, REGOBJ_OFF))
    print("  *(uint64_t*)(dummypage + 0x%x) = dummypage_phys + 0x%x;  // [regobj]=head node" % (REGOBJ_OFF, NODES_OFF))
    for i,(node,nxt,k1,k2,val,note) in enumerate(laid):
        o = NODES_OFF + i*NODE_SZ
        print("  *(uint64_t*)(dummypage + 0x%x) = 0x%x;               // node%d.next" % (o, nxt, i))
        print("  *(uint32_t*)(dummypage + 0x%x) = %d;                 // node%d.key1" % (o+8, k1, i))
        print("  *(uint32_t*)(dummypage + 0x%x) = %d;                 // node%d.key2" % (o+0x10, k2, i))
        print("  *(uint64_t*)(dummypage + 0x%x) = 0x%x;      // node%d.value" % (o+0x18, val, i))

if __name__ == "__main__":
    import sys
    dp = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x10006ff4000  # example
    build(dp)
