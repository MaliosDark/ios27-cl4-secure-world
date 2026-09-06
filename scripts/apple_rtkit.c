/*
 * Apple RTKit coprocessor emulation.
 *
 * We play the coprocessor side of the ASC mailbox so the guest's RTBuddy
 * driver can finish its handshake and reach a device-specific protocol.
 *
 * Register layout: Linux drivers/soc/apple/mailbox.c (GPL-2).
 * Protocol:        Linux drivers/soc/apple/rtkit.c   (GPL-2).
 */
#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "system/address-spaces.h"
#include "hw/arm/apple_rtkit.h"
#include "qemu/timer.h"

/* ---- ASC mailbox registers ---- */
#define ASC_CPU_CONTROL       0x044
#define ASC_CPU_CONTROL_RUN   BIT(4)
#define ASC_A2I_CONTROL       0x110
#define ASC_I2A_CONTROL       0x114
#define ASC_A2I_SEND0         0x800
#define ASC_A2I_SEND1         0x808
#define ASC_A2I_RECV0         0x810
#define ASC_A2I_RECV1         0x818
#define ASC_I2A_SEND0         0x820
#define ASC_I2A_SEND1         0x828
#define ASC_I2A_RECV0         0x830
#define ASC_I2A_RECV1         0x838
#define ASC_CTRL_FULL         BIT(16)
#define ASC_CTRL_EMPTY        BIT(17)

/* ---- RTKit management protocol (endpoint 0) ---- */
#define MGMT_EP               0
#define MGMT_TYPE_SHIFT       52          /* msg bits [59:52] */
#define MGMT_TYPE_MASK        0xffULL

#define MGMT_HELLO            1
#define MGMT_HELLO_REPLY      2
#define MGMT_STARTEP          5
#define MGMT_IOP_PWR          6
#define MGMT_IOP_PWR_ACK      7
#define MGMT_EPMAP            8
#define MGMT_AP_PWR           0xb

#define HELLO_MINVER(x)       ((x) & 0xffff)
#define HELLO_MAXVER(x)       (((x) >> 16) & 0xffff)
#define EPMAP_LAST            BIT_ULL(51)
#define EPMAP_BASE_SHIFT      32
#define EPMAP_BASE_MASK       0x7ULL
#define EPMAP_BITMAP_MASK     0xffffffffULL
#define EPMAP_REPLY_MORE      BIT_ULL(0)
#define STARTEP_EP_SHIFT      32
#define STARTEP_EP_MASK       0xffULL

#define RTKIT_VER_MIN         11
#define RTKIT_VER_MAX         12

/* Standard endpoints a coprocessor exposes before any device-specific one. */
#define EP_CRASHLOG           1
#define EP_SYSLOG             2
#define EP_DEBUG              3
#define EP_IOREPORTING        4
#define EP_OSLOG              8

/* Buffer requests arrive on the log endpoints as a request for the guest to
 * allocate shared memory; bits per Linux rtkit.c. */
#define BUFFER_REQUEST        1
#define BUFFER_SIZE_SHIFT     44
#define BUFFER_SIZE_MASK      0xffULL
#define BUFFER_IOVA_MASK      0xfffffffffffULL

static void rtkit_update_irq(AppleRTKit *rtk)
{
    qemu_set_irq(rtk->irq, rtk->count > 0);
}

void apple_rtkit_send(AppleRTKit *rtk, uint32_t ep, uint64_t msg)
{
    if (rtk->count == (int)ARRAY_SIZE(rtk->q)) {
        printf("[rtkit:%s] I2A queue full, dropping ep=0x%x\n", rtk->name, ep);
        return;
    }
    int slot = (rtk->head + rtk->count) % ARRAY_SIZE(rtk->q);
    rtk->q[slot].msg = msg;
    rtk->q[slot].ep = ep;
    rtk->count++;
    rtkit_update_irq(rtk);
}

static void mgmt_send(AppleRTKit *rtk, uint64_t type, uint64_t payload)
{
    apple_rtkit_send(rtk, MGMT_EP, (type << MGMT_TYPE_SHIFT) | payload);
}

void apple_rtkit_add_endpoint(AppleRTKit *rtk, uint32_t ep, const char *name,
                              RTKitEpHandler handler, void *opaque)
{
    if (ep >= RTKIT_MAX_ENDPOINTS) {
        return;
    }
    rtk->eps[ep].present = true;
    rtk->eps[ep].name = name;
    rtk->eps[ep].handler = handler;
    rtk->eps[ep].opaque = opaque;
}

void apple_rtkit_boot(AppleRTKit *rtk)
{
    if (rtk->hello_sent) {
        return;
    }
    rtk->hello_sent = true;
    rtk->running = true;
    printf("[rtkit:%s] boot -> HELLO(min=%d,max=%d)\n",
           rtk->name, RTKIT_VER_MIN, RTKIT_VER_MAX);
    fflush(stdout);
    mgmt_send(rtk, MGMT_HELLO,
              ((uint64_t)RTKIT_VER_MAX << 16) | RTKIT_VER_MIN);
}

/* Advertise every endpoint we have, in 32-bit bitmap chunks. */
static void send_epmap(AppleRTKit *rtk)
{
    uint32_t base = 0;
    uint64_t bitmap = 0;
    int last_base = 0;

    for (int ep = 0; ep < RTKIT_MAX_ENDPOINTS; ep++) {
        if (rtk->eps[ep].present) {
            last_base = ep / 32;
        }
    }

    for (base = 0; base <= (uint32_t)last_base; base++) {
        bitmap = 0;
        for (int bit = 0; bit < 32; bit++) {
            int ep = base * 32 + bit;
            if (ep < RTKIT_MAX_ENDPOINTS && rtk->eps[ep].present) {
                bitmap |= 1ULL << bit;
            }
        }
        uint64_t payload = ((uint64_t)base << EPMAP_BASE_SHIFT) |
                           (bitmap & EPMAP_BITMAP_MASK);
        if (base == (uint32_t)last_base) {
            payload |= EPMAP_LAST;
        }
        printf("[rtkit:%s] EPMAP base=%u bitmap=0x%08llx%s\n", rtk->name, base,
               (unsigned long long)bitmap,
               (base == (uint32_t)last_base) ? " (last)" : "");
        mgmt_send(rtk, MGMT_EPMAP, payload);
    }
    fflush(stdout);
}

static void handle_mgmt(AppleRTKit *rtk, uint64_t msg)
{
    uint64_t type = (msg >> MGMT_TYPE_SHIFT) & MGMT_TYPE_MASK;

    switch (type) {
    case MGMT_HELLO_REPLY: {
        int want = HELLO_MINVER(msg);
        rtk->version = want;
        printf("[rtkit:%s] HELLO_REPLY, version %d -> sending EPMAP\n",
               rtk->name, want);
        fflush(stdout);
        send_epmap(rtk);
        break;
    }
    case MGMT_EPMAP:
        /* The guest acknowledges each chunk; nothing more to do. */
        break;
    case MGMT_STARTEP: {
        uint32_t ep = (msg >> STARTEP_EP_SHIFT) & STARTEP_EP_MASK;
        if (ep < RTKIT_MAX_ENDPOINTS && rtk->eps[ep].present) {
            rtk->eps[ep].started = true;
            printf("[rtkit:%s] STARTEP 0x%x (%s)\n", rtk->name, ep,
                   rtk->eps[ep].name ? rtk->eps[ep].name : "?");
        } else {
            printf("[rtkit:%s] STARTEP 0x%x (not advertised)\n", rtk->name, ep);
        }
        fflush(stdout);
        break;
    }
    case MGMT_IOP_PWR:
        printf("[rtkit:%s] SET_IOP_PWR_STATE 0x%llx -> ack\n", rtk->name,
               (unsigned long long)(msg & 0xffff));
        fflush(stdout);
        mgmt_send(rtk, MGMT_IOP_PWR_ACK, msg & 0xffff);
        break;
    case MGMT_AP_PWR:
        printf("[rtkit:%s] SET_AP_PWR_STATE 0x%llx -> ack\n", rtk->name,
               (unsigned long long)(msg & 0xffff));
        fflush(stdout);
        mgmt_send(rtk, MGMT_AP_PWR, msg & 0xffff);
        break;
    default:
        printf("[rtkit:%s] mgmt type %llu payload 0x%llx (unhandled)\n",
               rtk->name, (unsigned long long)type,
               (unsigned long long)(msg & 0xfffffffffffffULL));
        fflush(stdout);
        break;
    }
}

/*
 * The log endpoints (crashlog/syslog/ioreporting/oslog) start by asking the
 * guest for a shared buffer. We answer the request so the guest allocates one
 * and hands back an IOVA, which we record: those buffers are where a real
 * coprocessor would write, and where the DCP protocol will need to read/write.
 */
static bool handle_log_ep(AppleRTKit *rtk, uint32_t ep, uint64_t msg,
                          void *opaque)
{
    uint64_t type = (msg >> MGMT_TYPE_SHIFT) & MGMT_TYPE_MASK;

    if (type == BUFFER_REQUEST) {
        uint64_t iova = msg & BUFFER_IOVA_MASK;
        uint32_t size = (msg >> BUFFER_SIZE_SHIFT) & BUFFER_SIZE_MASK;
        for (size_t i = 0; i < ARRAY_SIZE(rtk->bufs); i++) {
            if (!rtk->bufs[i].valid) {
                rtk->bufs[i].iova = iova;
                rtk->bufs[i].size = size;
                rtk->bufs[i].valid = true;
                break;
            }
        }
        printf("[rtkit:%s] ep 0x%x buffer at iova 0x%llx size %u pages\n",
               rtk->name, ep, (unsigned long long)iova, size);
        fflush(stdout);
        return true;
    }

    printf("[rtkit:%s] ep 0x%x msg 0x%016llx (log endpoint, ignored)\n",
           rtk->name, ep, (unsigned long long)msg);
    fflush(stdout);
    return true;
}

static void handle_a2i(AppleRTKit *rtk, uint64_t msg, uint32_t ep_word)
{
    uint32_t ep = ep_word & 0xff;

    if (ep == MGMT_EP) {
        handle_mgmt(rtk, msg);
        return;
    }

    if (ep < RTKIT_MAX_ENDPOINTS && rtk->eps[ep].handler) {
        if (rtk->eps[ep].handler(rtk, ep, msg, rtk->eps[ep].opaque)) {
            return;
        }
    }

    /* Unhandled traffic is the map of the protocol we still have to learn. */
    printf("[rtkit:%s] UNHANDLED ep=0x%x msg=0x%016llx\n",
           rtk->name, ep, (unsigned long long)msg);
    fflush(stdout);
}

static uint64_t rtkit_read(void *opaque, hwaddr off, unsigned size)
{
    AppleRTKit *rtk = opaque;
    uint64_t v = 0;

    switch (off) {
    case ASC_CPU_CONTROL:
        v = rtk->cpu_control;
        break;
    case ASC_I2A_CONTROL:
        v = rtk->count ? 0 : ASC_CTRL_EMPTY;
        break;
    case ASC_A2I_CONTROL:
        v = ASC_CTRL_EMPTY;      /* we drain instantly */
        break;
    case ASC_I2A_RECV0:
        v = rtk->count ? rtk->q[rtk->head].msg : 0;
        break;
    case ASC_I2A_RECV1:
        if (rtk->count) {
            v = rtk->q[rtk->head].ep;
            rtk->head = (rtk->head + 1) % ARRAY_SIZE(rtk->q);
            rtk->count--;
            rtkit_update_irq(rtk);
        }
        break;
    default:
        break;
    }

    if (rtk->trace_budget > 0 && rtk->hello_sent) {
        rtk->trace_budget--;
        printf("[rtkit:%s] read  +0x%03llx = 0x%llx\n", rtk->name,
               (unsigned long long)off, (unsigned long long)v);
        fflush(stdout);
    }
    return v;
}

static void rtkit_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    AppleRTKit *rtk = opaque;

    if (rtk->trace_budget > 0) {
        rtk->trace_budget--;
        printf("[rtkit:%s] write +0x%03llx = 0x%llx\n", rtk->name,
               (unsigned long long)off, (unsigned long long)val);
        fflush(stdout);
    }

    switch (off) {
    case ASC_CPU_CONTROL:
        rtk->cpu_control = val;
        if ((val & ASC_CPU_CONTROL_RUN) && !rtk->running) {
            printf("[rtkit:%s] CPU_CONTROL RUN\n", rtk->name);
            fflush(stdout);
            apple_rtkit_boot(rtk);
        }
        break;
    case ASC_A2I_SEND0:
        rtk->a2i_msg = val;
        break;
    case ASC_A2I_SEND1:
        handle_a2i(rtk, rtk->a2i_msg, (uint32_t)val);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps rtkit_ops = {
    .read = rtkit_read,
    .write = rtkit_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

static void rtkit_announce_cb(void *opaque)
{
    apple_rtkit_boot((AppleRTKit *)opaque);
}

void apple_rtkit_announce_after(AppleRTKit *rtk, int seconds)
{
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, rtkit_announce_cb, rtk);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + (int64_t)seconds * 1000);
    printf("[rtkit:%s] will self-announce in %ds\n", rtk->name, seconds);
    fflush(stdout);
}

AppleRTKit *apple_rtkit_new(const char *name, hwaddr base, uint64_t size,
                            qemu_irq irq)
{
    AppleRTKit *rtk = g_new0(AppleRTKit, 1);

    rtk->name = name;
    rtk->irq = irq;
    rtk->trace_budget = 200;

    /* Every RTKit coprocessor exposes these before anything device-specific. */
    apple_rtkit_add_endpoint(rtk, EP_CRASHLOG,     "crashlog",    handle_log_ep, NULL);
    apple_rtkit_add_endpoint(rtk, EP_SYSLOG,       "syslog",      handle_log_ep, NULL);
    apple_rtkit_add_endpoint(rtk, EP_DEBUG,        "debug",       handle_log_ep, NULL);
    apple_rtkit_add_endpoint(rtk, EP_IOREPORTING,  "ioreporting", handle_log_ep, NULL);
    apple_rtkit_add_endpoint(rtk, EP_OSLOG,        "oslog",       handle_log_ep, NULL);

    memory_region_init_io(&rtk->mr, NULL, &rtkit_ops, rtk, name, size);
    memory_region_add_subregion_overlap(get_system_memory(), base, &rtk->mr, 1);

    printf("[rtkit:%s] mailbox 0x%llx + 0x%llx\n", name,
           (unsigned long long)base, (unsigned long long)size);
    fflush(stdout);
    return rtk;
}
