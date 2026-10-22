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
#include "qemu/timer.h"
#include "ui/vgafont.h"
#include <math.h>
#include <string.h>
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

    /* Panel scanout: our DCP drives the display just like the real one --
     * it writes frames straight into the framebuffer the loader reserved.
     * Until the guest IOMFB path delivers real surfaces, this paints a live
     * bring-up frame so the panel is visibly driven end-to-end. */
    QEMUTimer *paint;
    uint32_t frame;
    bool surface_live;   /* set once the guest AFK transport is up */
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

    case RBEP_RECV: {
        /* The guest signalled it wrote into the TX ring. Dump the ring memory so
         * we can see the AFK header (rptr/wptr) and the IOMFB message bytes and
         * build out the RPC. bfr_dva is a DART DVA; the DART model here does not
         * translate, so try a direct physical read first. */
        uint8_t buf[0x140];
        MemTxResult r = address_space_read(&address_space_memory, s->bfr_dva,
                                           MEMTXATTRS_UNSPECIFIED, buf, sizeof buf);
        printf("[dcp] AFK RECV #%llu (dva 0x%llx, read=%d): TX ring dump:\n",
               (unsigned long long)s->msgs, (unsigned long long)s->bfr_dva, (int)r);
        for (int o = 0; o < (int)sizeof buf; o += 16) {
            printf("  +%03x:", o);
            for (int i = 0; i < 16; i++) printf(" %02x", buf[o + i]);
            printf("  ");
            for (int i = 0; i < 16; i++) {
                char c = buf[o + i];
                putchar((c >= 0x20 && c < 0x7f) ? c : '.');
            }
            printf("\n");
        }
        fflush(stdout);
        return true;
    }

    default:
        printf("[dcp] AFK unhandled type 0x%llx msg 0x%016llx\n",
               (unsigned long long)type, (unsigned long long)msg);
        fflush(stdout);
        return true;
    }
}



/* ---- On-panel console: the guest's real boot log, rendered to the display ----
 * The emulated UART tees every transmitted byte here (see exynos4210_uart.c),
 * so the DCP paints the actual iOS kernel log onto the iPhone panel. */
#define CONS_ROWS 256
#define CONS_COLS 128
static char cons[CONS_ROWS][CONS_COLS];
static int  cons_row, cons_col;
static bool cons_any;

/* Real boot progress, inferred from the guest's own log lines. */
static int boot_stage;   /* 0..5 */
static bool boot_panic;
static const char *const STAGE_NAME[] = {
    "Booting secure world",
    "Starting XNU kernel",
    "Mounting filesystem",
    "Loading drivers",
    "Starting services",
    "iOS is up",
};
static void boot_check_stage(const char *ln)
{
    if (strstr(ln, "panic(") || strstr(ln, "Panicked")) boot_panic = true;
    if (strstr(ln, "hello from launchd") || strstr(ln, "ignition sequence complete")) boot_stage = 5;
    else if (strstr(ln, "launchd") || strstr(ln, "ignition") || strstr(ln, "BSD root")) { if (boot_stage < 4) boot_stage = 4; }
    else if (strstr(ln, "RTBuddy") || strstr(ln, "AppleARM") || strstr(ln, "IOService")) { if (boot_stage < 3) boot_stage = 3; }
    else if (strstr(ln, "apfs") || strstr(ln, "mountroot") || strstr(ln, "rootfs") || strstr(ln, "md0")) { if (boot_stage < 2) boot_stage = 2; }
    else if (strstr(ln, "virtBase") || strstr(ln, "Darwin") || strstr(ln, "xnu") || strstr(ln, "SPTM")) { if (boot_stage < 1) boot_stage = 1; }
}

static void cons_newline(void)
{
    boot_check_stage(cons[cons_row]);
    cons_col = 0;
    cons_row++;
    if (cons_row >= CONS_ROWS) {
        memmove(cons[0], cons[1], (CONS_ROWS - 1) * CONS_COLS);
        cons_row = CONS_ROWS - 1;
    }
    memset(cons[cons_row], 0, CONS_COLS);
}

void dcp_console_feed(const uint8_t *buf, int len);
void dcp_console_feed(const uint8_t *buf, int len)
{
    for (; len-- > 0; buf++) {
        char c = (char)*buf;
        if (c == '\n') { cons_newline(); }
        else if (c == '\r') { cons_col = 0; }
        else if (c == '\t') { cons_col = (cons_col + 8) & ~7; if (cons_col >= CONS_COLS - 1) cons_newline(); }
        else if ((uint8_t)c >= 0x20 && (uint8_t)c < 0x7f) {
            if (cons_col >= CONS_COLS - 1) cons_newline();
            cons[cons_row][cons_col++] = c;
        }
        cons_any = true;
    }
}

static void putglyph(uint32_t *fb, int W, int H, int px, int py, unsigned char c, uint32_t col)
{
    const uint8_t *g = &vgafont16[(unsigned)c * 16];
    for (int r = 0; r < 16; r++) {
        int y = py + r; if (y < 0 || y >= H) continue;
        uint8_t bits = g[r];
        for (int b = 0; b < 8; b++) {
            if (bits & (0x80 >> b)) { int x = px + b; if (x >= 0 && x < W) fb[y * W + x] = col; }
        }
    }
}

static void puts_fb(uint32_t *fb, int W, int H, int px, int py, const char *str, uint32_t col)
{
    for (; *str; str++, px += 8) putglyph(fb, W, H, px, py, (unsigned char)*str, col);
}

/* Compose one frame into guest framebuffer RAM (PIXMAN_x8r8g8b8: 0x00RRGGBB). */
static float g_prog;   /* eased 0..1 */

static void fill_rect(uint32_t *fb, int W, int H, int x0, int y0, int w, int h, uint32_t c)
{
    for (int y = y0; y < y0 + h; y++) { if (y < 0 || y >= H) continue;
        for (int x = x0; x < x0 + w; x++) { if (x >= 0 && x < W) fb[y * W + x] = c; } }
}

static void dcp_paint(AppleDCPState *s)
{
    int W = s->width, H = s->height;
    if (!W || !H || !s->fb_base) return;
    uint32_t *fb = g_malloc0((size_t)W * H * 4);
    int t = s->frame;

    /* ground: near-black with a faint top-lit gradient */
    for (int y = 0; y < H; y++) {
        int v = 3 + (5 * (H - y)) / H;
        uint32_t bg = ((uint32_t)(v/2) << 16) | ((uint32_t)v << 8) | (uint32_t)(v + 3);
        for (int x = 0; x < W; x++) fb[y * W + x] = bg;
    }

    /* device identity, centered near the top */
    puts_fb(fb, W, H, W/2 - 5*8, 70, "iPhone17,3", 0xdfeee8);
    puts_fb(fb, W, H, W/2 - 8*8 + 4, 92, "iOS 27  *  t8140", 0x5f8e82);

    /* progress ring, driven by the REAL boot stage */
    float target = boot_stage / 5.0f;
    g_prog += (target - g_prog) * 0.06f;
    if (g_prog > 1) g_prog = 1;
    int cx = W/2, cy = (int)(H * 0.30f), R = 92, TH = 7;
    for (int a = 0; a < 360; a++) {
        float rad = a * 3.14159265f / 180.0f;
        int filled = (a <= (int)(g_prog * 360));
        /* rotating comet head */
        int head = (t * 4) % 360;
        int near = ((a - head + 360) % 360) < 26;
        uint32_t col = boot_panic
            ? (filled ? (near ? 0xffe0d0 : 0xef5b5b) : 0x3a1414)
            : (filled ? (near ? 0xeafff6 : 0x33e0a8) : 0x14352c);
        for (int k = -TH; k <= TH; k++) {
            int x = cx + (int)((R + k) * sinf(rad));
            int y = cy - (int)((R + k) * cosf(rad));
            if (x >= 0 && x < W && y >= 0 && y < H) fb[y * W + x] = col;
        }
    }
    /* percentage in the ring */
    char pct[8]; int p = (int)(g_prog * 100 + 0.5f);
    snprintf(pct, sizeof pct, "%d%%", p);
    puts_fb(fb, W, H, cx - (int)strlen(pct)*4, cy - 8,
            boot_panic ? "!" : pct, boot_panic ? 0xef5b5b : 0xdfeee8);

    /* current stage label */
    const char *st = boot_panic ? "KERNEL PANIC -- see console"
                                : STAGE_NAME[boot_stage < 6 ? boot_stage : 5];
    puts_fb(fb, W, H, cx - (int)strlen(st)*4, cy + R + 26, st,
            boot_panic ? 0xef7b6b : 0x9fd8c6);

    /* live boot log in the lower panel */
    int top = (int)(H * 0.52f), line_h = 16, margin = 8;
    fill_rect(fb, W, H, 0, top - 10, W, 1, 0x123028);
    puts_fb(fb, W, H, margin, top - 26, "-- kernel console --", 0x3f6b5e);
    int vis = (H - top - 30) / line_h;
    int start = cons_row - vis + 1; if (start < 0) start = 0;
    for (int i = 0; i < vis; i++) {
        int rr = start + i; if (rr < 0 || rr >= CONS_ROWS) continue;
        int age = cons_row - rr;
        uint32_t col = age < 2 ? 0xbdf5e2 : age < 8 ? 0x46c99e : 0x2c7d64;
        for (int c = 0; c < CONS_COLS && cons[rr][c]; c++)
            putglyph(fb, W, H, margin + c * 8, top + i * line_h, (unsigned char)cons[rr][c], col);
    }

    if (!cons_any)
        puts_fb(fb, W, H, cx - 13*4, cy + R + 26, "powering on panel...", 0x46c99e);

    /* RGB scanout proof strip */
    for (int y = H - 5; y < H; y++)
        for (int x = 0; x < W; x++) {
            int seg = (x * 5) / W;
            fb[y * W + x] = seg==0?0xd02828 : seg==1?0x28d028 : seg==2?0x2858d0 : seg==3?0xd0d0d0 : 0x0a0a0a;
        }

    /* soft vignette so the panel reads like glass, not a flat buffer */
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            int ex = x < W - x ? x : W - x;
            int ey = y < H - y ? y : H - y;
            int e = ex < ey ? ex : ey;
            if (e < 40) {
                uint32_t p = fb[y * W + x];
                int sh = (40 - e);              /* 0..40 */
                int r = ((p >> 16) & 0xff) * (100 - sh) / 100;
                int g = ((p >> 8) & 0xff) * (100 - sh) / 100;
                int b = (p & 0xff) * (100 - sh) / 100;
                fb[y * W + x] = (r << 16) | (g << 8) | b;
            }
        }
    }
    address_space_write(&address_space_memory, s->fb_base, MEMTXATTRS_UNSPECIFIED, fb, (size_t)W * H * 4);
    g_free(fb);
    s->frame++;
}

static void dcp_tick(void *opaque)
{
    AppleDCPState *s = opaque;
    dcp_paint(s);
    timer_mod(s->paint, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + 40);
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

    /* Drive the panel: paint a live bring-up frame ~25fps. This lights the
     * DarwinFB console the instant the DCP device exists, proving the scanout
     * path end-to-end while the guest IOMFB surface path is built out. */
    if (fb_base && !getenv("DCP_NO_SCANOUT")) {
        s->paint = timer_new_ms(QEMU_CLOCK_REALTIME, dcp_tick, s);
        timer_mod(s->paint, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + 50);
        printf("[dcp] panel scanout ON -> framebuffer 0x%llx (%ux%u)\n",
               (unsigned long long)fb_base, width, height);
    }
    fflush(stdout);
}
