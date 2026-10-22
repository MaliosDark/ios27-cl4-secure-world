#ifndef HW_ARM_APPLE_DCP_H
#define HW_ARM_APPLE_DCP_H

#include "qemu/osdep.h"
#include "hw/arm/apple_rtkit.h"

/* Advertise the DCP endpoints on an RTKit coprocessor and bind them to the
 * framebuffer we will eventually scan out. */
void apple_dcp_attach(AppleRTKit *rtk, uint32_t width, uint32_t height,
                      hwaddr fb_base);

#endif
