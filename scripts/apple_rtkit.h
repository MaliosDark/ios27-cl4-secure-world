/*
 * Apple RTKit coprocessor emulation.
 *
 * Stands in for an RTKit/ASC coprocessor (DCP, ANS, ...) so the guest's
 * RTBuddy driver can complete its handshake and start talking a
 * device-specific protocol to us.
 *
 * Register layout: Linux drivers/soc/apple/mailbox.c (GPL-2).
 * Protocol:        Linux drivers/soc/apple/rtkit.c   (GPL-2).
 */
#ifndef HW_ARM_APPLE_RTKIT_H
#define HW_ARM_APPLE_RTKIT_H

#include "qemu/osdep.h"
#include "system/memory.h"
#include "hw/core/irq.h"

#define RTKIT_MAX_ENDPOINTS 64

typedef struct AppleRTKit AppleRTKit;

/*
 * An endpoint handler. Return true if the message was consumed; false leaves
 * it to be logged as unhandled, which is how the protocol gets mapped out.
 */
typedef bool (*RTKitEpHandler)(AppleRTKit *rtk, uint32_t ep,
                               uint64_t msg, void *opaque);

typedef struct RTKitEndpoint {
    bool present;          /* advertised in EPMAP */
    bool started;          /* guest sent STARTEP */
    const char *name;      /* for logs */
    RTKitEpHandler handler;
    void *opaque;
} RTKitEndpoint;

struct AppleRTKit {
    MemoryRegion mr;
    qemu_irq irq;
    const char *name;

    /* I2A queue: messages we are sending to the guest. */
    struct { uint64_t msg; uint32_t ep; } q[64];
    int head, count;

    /* A2I staging: the guest writes SEND0 then SEND1. */
    uint64_t a2i_msg;

    uint32_t cpu_control;
    bool running;
    bool hello_sent;
    int version;           /* negotiated RTKit protocol version */

    RTKitEndpoint eps[RTKIT_MAX_ENDPOINTS];

    /* Shared-memory buffers the coprocessor asked the guest to allocate. */
    struct { uint64_t iova; uint32_t size; bool valid; } bufs[8];

    int trace_budget;
};

/* Create the device over one MMIO window and wire it to an interrupt line. */
AppleRTKit *apple_rtkit_new(const char *name, hwaddr base, uint64_t size,
                            qemu_irq irq);

/* Advertise an endpoint so it appears in EPMAP and can be started. */
void apple_rtkit_add_endpoint(AppleRTKit *rtk, uint32_t ep, const char *name,
                              RTKitEpHandler handler, void *opaque);

/* Queue a message to the guest on an endpoint and raise the interrupt. */
void apple_rtkit_send(AppleRTKit *rtk, uint32_t ep, uint64_t msg);

/* Bring the coprocessor up (say HELLO) without waiting for CPU_CONTROL. */
void apple_rtkit_boot(AppleRTKit *rtk);

/* Boot the coprocessor N seconds into the run, after drivers have attached. */
void apple_rtkit_announce_after(AppleRTKit *rtk, int seconds);

#endif /* HW_ARM_APPLE_RTKIT_H */
