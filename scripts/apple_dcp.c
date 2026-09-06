/*
 * Apple DCP (Display CoProcessor) endpoint emulation.
 *
 * The display stack binds:
 *   RTBuddy(DCP) -> RTBuddyEndpointService "DCPEndpoint24"
 *                -> AppleDCPLinkServiceSoC -> AppleCLCD2 on disp0
 *                -> IOMobileFramebuffer
 *
 * Endpoint 0x24 speaks AFK (Apple Firmware Kit): a ring-buffer transport in
 * shared memory, on top of which the IOMFB RPC runs. This models the
 * coprocessor side of AFK far enough to complete the transport handshake, and
 * logs the IOMFB traffic that then flows so the RPC can be decoded.
 *
 * AFK framing and field layout: Asahi Linux drivers/gpu/drm/apple/afk.c (GPL-2).
 * The roles are mirrored here: Asahi is the application processor, we are the
 * coprocessor, so sends/receives are swapped relative to that reference.
 */
#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "system/address-spaces.h"
#include "hw/arm/apple_rtkit.h"
#include "hw/arm/apple_dcp.h"

#define DCP_EP_MAIN     0x24    /* "DCPEndpoint24" */
#define DCP_EP_ALT      0x25
#define DCP_EP_EPIC     0x23

/* ---- AFK ring-buffer endpoint protocol (afk.c) ---- */
#define RBEP_TYPE_SHIFT   48
#define RBEP_TYPE_MASK    0xffffULL

#define RBEP_INIT         0x80
#define RBEP_INIT_ACK     0xa0
#define RBEP_GETBUF       0x89
#define RBEP_GETBUF_ACK   0xa1
#define RBEP_INIT_TX      0x8a
#define RBEP_INIT_RX      0x8b
#define RBEP_START        0xa3
#define RBEP_START_ACK    0xa4
#define RBEP_RECV         0x85
#define RBEP_SHUTDOWN     0xc0
#define RBEP_SHUTDOWN_ACK 0xc1

#define BLOCK_SHIFT       6
#define GETBUF_SIZE_SHIFT 16
#define GETBUF_SIZE_MASK  0xffffULL
#define GETBUF_TAG_MASK   0xffffULL
#define GETBUF_ACK_DVA_MASK 0xffffffffffffULL   /* GENMASK(47,0) */
#define INITRB_OFFSET_SHIFT 32
#define INITRB_SIZE_SHIFT   16

typedef struct AppleDCPState {
    AppleRTKit *rtk;
    uint32_t width, height, stride;
    hwaddr fb_base;

    /* AFK transport state for endpoint 0x24. */
    bool afk_inited;
    uint64_t bfr_dva;        /* shared buffer the guest allocated for us */
    uint32_t bfr_size;
    bool tx_ready, rx_ready, started;

    uint64_t msgs;
    int trace;
} AppleDCPState;

static uint64_t rbep(uint64_t type)
{
    return type << RBEP_TYPE_SHIFT;
}

/*
 * AFK handshake, coprocessor side. The guest driver opens the endpoint by
 * sending RBEP_INIT; we then drive the ring-buffer setup: ack, request a
 * shared buffer, describe the TX and RX rings inside it, and start.
 */
static bool dcp_ep_handler(AppleRTKit *rtk, uint32_t ep, uint64_t msg,
                           void *opaque)
{
    AppleDCPState *s = opaque;
    uint64_t type = (msg >> RBEP_TYPE_SHIFT) & RBEP_TYPE_MASK;

    s->msgs++;
    if (s->trace > 0) {
        s->trace--;
        printf("[dcp] ep=0x%02x afk-type=0x%llx msg=0x%016llx (#%llu)\n",
               ep, (unsigned long long)type, (unsigned long long)msg,
               (unsigned long long)s->msgs);
        fflush(stdout);
    }

    switch (type) {
    case RBEP_INIT:
        /* Ack, then ask the guest to allocate a shared buffer for the rings.
         * One 0x1000-byte block is plenty for the handshake. */
        apple_rtkit_send(rtk, ep, rbep(RBEP_INIT_ACK));
        apple_rtkit_send(rtk, ep,
                         rbep(RBEP_GETBUF) |
                         ((uint64_t)(0x1000 >> BLOCK_SHIFT) << GETBUF_SIZE_SHIFT) |
                         0x1 /* tag */);
        printf("[dcp] AFK INIT -> INIT_ACK + GETBUF\n");
        fflush(stdout);
        return true;

    case RBEP_GETBUF_ACK:
        s->bfr_dva = msg & GETBUF_ACK_DVA_MASK;
        printf("[dcp] AFK GETBUF_ACK: buffer dva 0x%llx\n",
               (unsigned long long)s->bfr_dva);
        /* Describe TX and RX rings within the buffer (first/second halves). */
        apple_rtkit_send(rtk, ep,
                         rbep(RBEP_INIT_TX) |
                         ((uint64_t)0 << INITRB_OFFSET_SHIFT) |
                         ((uint64_t)(0x800 >> BLOCK_SHIFT) << INITRB_SIZE_SHIFT) |
                         0x1);
        apple_rtkit_send(rtk, ep,
                         rbep(RBEP_INIT_RX) |
                         ((uint64_t)(0x800 >> BLOCK_SHIFT) << INITRB_OFFSET_SHIFT) |
                         ((uint64_t)(0x800 >> BLOCK_SHIFT) << INITRB_SIZE_SHIFT) |
                         0x2);
        apple_rtkit_send(rtk, ep, rbep(RBEP_START));
        s->afk_inited = true;
        fflush(stdout);
        return true;

    case RBEP_START_ACK:
        s->started = true;
        printf("[dcp] AFK transport up on endpoint 0x%02x -- IOMFB can flow\n", ep);
        fflush(stdout);
        return true;

    case RBEP_RECV:
        /* The guest signalled it wrote into the TX ring. Decoding the IOMFB
         * message means reading the ring in shared memory; for now, surface
         * that we got here so the next stage has a foothold. */
        printf("[dcp] AFK RECV: guest posted an IOMFB message (ring at dva 0x%llx)\n",
               (unsigned long long)s->bfr_dva);
        fflush(stdout);
        return true;

    default:
        printf("[dcp] AFK unhandled type 0x%llx msg 0x%016llx\n",
               (unsigned long long)type, (unsigned long long)msg);
        fflush(stdout);
        return true;
    }
}

void apple_dcp_attach(AppleRTKit *rtk, uint32_t width, uint32_t height,
                      hwaddr fb_base)
{
    AppleDCPState *s = g_new0(AppleDCPState, 1);

    s->rtk = rtk;
    s->width = width;
    s->height = height;
    s->stride = width * 4;
    s->fb_base = fb_base;
    s->trace = 400;

    apple_rtkit_add_endpoint(rtk, DCP_EP_EPIC,  "dcp-epic", dcp_ep_handler, s);
    apple_rtkit_add_endpoint(rtk, DCP_EP_MAIN,  "DCPEndpoint24", dcp_ep_handler, s);
    apple_rtkit_add_endpoint(rtk, DCP_EP_ALT,   "DCPEndpoint25", dcp_ep_handler, s);

    printf("[dcp] AFK endpoints 0x%02x/0x%02x/0x%02x, %ux%u fb at 0x%llx\n",
           DCP_EP_EPIC, DCP_EP_MAIN, DCP_EP_ALT, width, height,
           (unsigned long long)fb_base);
    fflush(stdout);
}
