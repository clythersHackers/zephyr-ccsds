#include "ccsds_tm_frame.h"

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "ccsds_crc16.h"
#include "ccsds_space_packet.h"

#ifdef CONFIG_AKIRA_CCSDS_RS
#include "ccsds_rs.h"
#endif

#define CCSDS_TM_MAX_VC_ID 7u
#define CCSDS_TM_VC_COUNT (CCSDS_TM_MAX_VC_ID + 1u)
#define CCSDS_TM_ROUTE_COUNT 32u
#define CCSDS_SPACE_PACKET_MIN_LEN (CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + 1u)
#define CCSDS_TM_ASM_LEN 4u
#define CCSDS_TM_PRIMARY_HDR_LEN 6u
#define CCSDS_TM_OCF_LEN 4u
#define CCSDS_TM_IDLE_VC_ID CCSDS_TM_MAX_VC_ID
#define CCSDS_TM_IDLE_FIRST_HEADER_POINTER 0x7feu
#define CCSDS_TM_NO_FIRST_HEADER_POINTER 0x7ffu
#define CCSDS_TM_FIRST_HEADER_POINTER_START 0u
#define CCSDS_TM_SECONDARY_HEADER_FLAG 0u
#define CCSDS_TM_SYNC_FLAG 0u
#define CCSDS_TM_PACKET_ORDER_FLAG 0u
#define CCSDS_TM_SEGMENT_LENGTH_ID 3u
#define CCSDS_TM_IDLE_APID CCSDS_APID_MAX
#define CCSDS_TM_ASM0 0x1au
#define CCSDS_TM_ASM1 0xcfu
#define CCSDS_TM_ASM2 0xfcu
#define CCSDS_TM_ASM3 0x1du

#ifdef CONFIG_AKIRA_CCSDS_RS
#define CCSDS_TM_FRAME_LEN CCSDS_RS_INTERLEAVED_DATA_LEN
#define CCSDS_TM_CODED_FRAME_LEN \
    (CCSDS_TM_ASM_LEN + CCSDS_TM_FRAME_LEN + CCSDS_RS_INTERLEAVED_PARITY_LEN)
#else
#define CCSDS_TM_FRAME_LEN CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN
#define CCSDS_TM_CODED_FRAME_LEN (CCSDS_TM_ASM_LEN + CCSDS_TM_FRAME_LEN)
#endif

#ifdef CONFIG_AKIRA_CCSDS_TM_FECF
#define CCSDS_TM_FECF_LEN CCSDS_CRC16_LEN
#else
#define CCSDS_TM_FECF_LEN 0u
#endif

BUILD_ASSERT(CONFIG_AKIRA_CCSDS_SPACECRAFT_ID <= 0x3ff,
             "CCSDS spacecraft ID must fit in 10 bits");
BUILD_ASSERT(CCSDS_TM_FRAME_LEN <= CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN,
             "configured TM frame workspace is smaller than generated frame");
BUILD_ASSERT(CCSDS_TM_FRAME_LEN >
                 (CCSDS_TM_PRIMARY_HDR_LEN + CCSDS_TM_OCF_LEN +
                  CCSDS_TM_FECF_LEN),
             "configured TM frame length is too small for TM overhead");
BUILD_ASSERT(CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH >=
                 CONFIG_AKIRA_CCSDS_TM_MAX_SPACE_PACKET_LEN,
             "TM queue depth must hold one maximum TM Space Packet");

struct ccsds_tm_vc {
    struct k_mutex write_lock;
    struct k_pipe pending;
    uint8_t pending_storage[CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH];
    size_t pending_len;

    size_t packet_rem;
    bool packet_is_idle;

    uint8_t vcfc;
    ccsds_tm_route_mask_t route_mask;
};

struct ccsds_tm_route {
    ccsds_tm_route_fn_t fn;
    void *user_data;
};

struct ccsds_tm_clcw_provider {
    ccsds_tm_clcw_provider_t fn;
    void *user_data;
};

static struct ccsds_tm_vc vcs[CCSDS_TM_VC_COUNT];
static struct ccsds_tm_route routes[CCSDS_TM_ROUTE_COUNT];
static struct ccsds_tm_clcw_provider clcw_provider;
static uint8_t frame_buf[CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN];
static uint8_t coded_frame_buf[CCSDS_TM_CODED_FRAME_LEN];
static struct k_work_delayable generator_work;
static struct k_mutex generator_lock;
static k_timeout_t generator_active_delay;
static k_timeout_t generator_idle_delay;
static uint8_t mcfc;
static uint8_t generator_last_vcid;
static bool generator_work_initialized;
static bool generator_running;
static bool generator_last_cycle_active;
static bool initialized;

static void route_frame(uint8_t vcid, const uint8_t *frame, size_t frame_len);

/* Return the total packet length encoded in the CCSDS primary header. */
static size_t packet_total_len(const uint8_t *packet)
{
    uint16_t length_field = ((uint16_t)packet[4] << 8) | packet[5];

    return CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + (size_t)length_field + 1u;
}

/* Check that a route registration names exactly one supported nonzero bit. */
static bool route_bit_is_valid(ccsds_tm_route_mask_t route_bit)
{
    if (route_bit == CCSDS_TM_ROUTE_NONE) {
        return false;
    }

    if ((route_bit & (route_bit - 1u)) != 0u) {
        return false;
    }

    return (route_bit & CCSDS_TM_SUPPORTED_ROUTE_MASK) != 0u;
}

/* Check that a per-VC route mask contains only supported route bits. */
static bool route_mask_is_valid(ccsds_tm_route_mask_t route_mask)
{
    return (route_mask & ~CCSDS_TM_SUPPORTED_ROUTE_MASK) == 0u;
}

/* Convert a validated single-bit route mask into its callback table index. */
static uint8_t route_bit_index(ccsds_tm_route_mask_t route_bit)
{
    uint8_t bit_num = 0u;

    while ((route_bit >> bit_num) != 1u) {
        bit_num++;
    }

    return bit_num;
}

static void write_be16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value >> 8);
    buf[1] = (uint8_t)value;
}

static void write_be32(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)value;
}

/* Build the TM primary header using the already-latched frame counters. */
static void build_primary_header(uint8_t *buf, uint8_t vcid,
                                 uint16_t first_header_pointer)
{
    uint16_t word0;
    uint16_t word2;

    word0 = ((uint16_t)(CONFIG_AKIRA_CCSDS_SPACECRAFT_ID & 0x3ffu) << 4) |
            ((uint16_t)(vcid & 0x7u) << 1) | 0x1u;
    word2 = ((uint16_t)(CCSDS_TM_SECONDARY_HEADER_FLAG & 0x1u) << 15) |
            ((uint16_t)(CCSDS_TM_SYNC_FLAG & 0x1u) << 14) |
            ((uint16_t)(CCSDS_TM_PACKET_ORDER_FLAG & 0x1u) << 13) |
            ((uint16_t)(CCSDS_TM_SEGMENT_LENGTH_ID & 0x3u) << 11) |
            (first_header_pointer & 0x7ffu);

    write_be16(&buf[0], word0);
    buf[2] = mcfc;
    buf[3] = vcs[vcid].vcfc;
    write_be16(&buf[4], word2);
}

/* Append the optional TM FECF at the end of the transfer frame body. */
static void append_fecf(void)
{
#ifdef CONFIG_AKIRA_CCSDS_TM_FECF
    uint16_t fecf;
    size_t fecf_offset = CCSDS_TM_FRAME_LEN - CCSDS_TM_FECF_LEN;

    fecf = ccsds_crc16_compute(frame_buf, fecf_offset);
    write_be16(&frame_buf[fecf_offset], fecf);
#endif
}

static void append_ocf(size_t ocf_offset)
{
    uint32_t clcw;

    if (clcw_provider.fn == NULL) {
        return;
    }

    if (clcw_provider.fn(&clcw, clcw_provider.user_data) != 0) {
        return;
    }

    write_be32(&frame_buf[ocf_offset], clcw);
}

/* Advance master and selected virtual-channel frame counters after emit. */
static void increment_frame_counters(uint8_t vcid)
{
    mcfc++;
    vcs[vcid].vcfc++;
}

/*
 * Fill remaining TM data bytes with one APID 2047 idle Space Packet when
 * possible. If fewer than the minimum packet bytes remain, zero-fill the tail.
 */
static void fill_idle_space_packet(uint8_t *buf, size_t len)
{
    if (len < CCSDS_SPACE_PACKET_MIN_LEN) {
        memset(buf, 0, len);
        return;
    }

    write_be16(&buf[0], CCSDS_TM_IDLE_APID);
    write_be16(&buf[2], ((uint16_t)CCSDS_SEQUENCE_UNSEGMENTED << 14));
    write_be16(&buf[4],
               (uint16_t)(len - CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN - 1u));
    memset(&buf[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN], 0,
           len - CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN);
}

/*
 * Drain exactly len bytes from a VC pipe while keeping the mirror pending_len
 * counter synchronized for deterministic generator selection.
 */
static int read_pending_bytes(struct ccsds_tm_vc *vc, uint8_t *buf, size_t len)
{
    size_t read_len = 0u;

    while (read_len < len) {
        int ret = k_pipe_read(&vc->pending, &buf[read_len],
                              len - read_len, K_NO_WAIT);

        if (ret < 0) {
            return ret;
        }

        if (ret == 0) {
            return -EIO;
        }

        read_len += (size_t)ret;
        vc->pending_len -= (size_t)ret;
    }

    return 0;
}

/* Build a standalone idle frame for the configured idle VC. */
static size_t build_idle_transfer_frame(uint8_t vcid)
{
    size_t data_len = CCSDS_TM_FRAME_LEN - CCSDS_TM_PRIMARY_HDR_LEN -
                      CCSDS_TM_OCF_LEN - CCSDS_TM_FECF_LEN;
    __maybe_unused size_t ocf_offset = CCSDS_TM_PRIMARY_HDR_LEN + data_len;

    memset(frame_buf, 0, CCSDS_TM_FRAME_LEN);
    build_primary_header(frame_buf, vcid, CCSDS_TM_IDLE_FIRST_HEADER_POINTER);
    append_ocf(ocf_offset);
    append_fecf();

    __ASSERT_NO_MSG(ocf_offset + CCSDS_TM_OCF_LEN + CCSDS_TM_FECF_LEN ==
                    CCSDS_TM_FRAME_LEN);

    increment_frame_counters(vcid);

    return CCSDS_TM_FRAME_LEN;
}

/*
 * Build one packet-bearing TM frame for a selected VC.
 *
 * The formatter owns all padding decisions. It first emits any unfinished
 * packet continuation, then starts as many queued packets as will fit, and
 * finally fills remaining data bytes with APID 2047 idle data. The first header
 * pointer is set to the offset of the first packet start in this frame, or to
 * 0x7ff when the frame contains continuation only and no packet starts.
 */
static int build_packet_transfer_frame(uint8_t vcid, size_t *frame_len)
{
    struct ccsds_tm_vc *vc = &vcs[vcid];
    size_t data_len = CCSDS_TM_FRAME_LEN - CCSDS_TM_PRIMARY_HDR_LEN -
                      CCSDS_TM_OCF_LEN - CCSDS_TM_FECF_LEN;
    __maybe_unused size_t ocf_offset = CCSDS_TM_PRIMARY_HDR_LEN + data_len;
    uint8_t *data = &frame_buf[CCSDS_TM_PRIMARY_HDR_LEN];
    size_t used = 0u;
    uint16_t first_header_pointer = CCSDS_TM_NO_FIRST_HEADER_POINTER;
    int ret;

    memset(frame_buf, 0, CCSDS_TM_FRAME_LEN);

    k_mutex_lock(&vc->write_lock, K_FOREVER);

    while (used < data_len && (vc->packet_rem > 0u || vc->pending_len > 0u)) {
        size_t space = data_len - used;
        size_t chunk_len;

        if (vc->packet_rem > 0u) {
            chunk_len = MIN((size_t)vc->packet_rem, space);
            ret = read_pending_bytes(vc, &data[used], chunk_len);
            if (ret != 0) {
                goto out_unlock;
            }

            vc->packet_rem -= chunk_len;
            used += chunk_len;
            continue;
        }

        if (space < CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN) {
            break;
        }

        if (vc->pending_len < CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN) {
            ret = -EIO;
            goto out_unlock;
        }

        if (first_header_pointer == CCSDS_TM_NO_FIRST_HEADER_POINTER) {
            first_header_pointer = (uint16_t)used;
        }

        ret = read_pending_bytes(vc, &data[used],
                                 CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN);
        if (ret != 0) {
            goto out_unlock;
        }

        vc->packet_rem = packet_total_len(&data[used]) -
                         CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN;
        used += CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN;
    }

    if (used < data_len) {
        if (first_header_pointer == CCSDS_TM_NO_FIRST_HEADER_POINTER &&
            data_len - used >= CCSDS_SPACE_PACKET_MIN_LEN) {
            first_header_pointer = (uint16_t)used;
        }
        fill_idle_space_packet(&data[used], data_len - used);
    }

    build_primary_header(frame_buf, vcid, first_header_pointer);
    append_ocf(ocf_offset);
    append_fecf();

    __ASSERT_NO_MSG(ocf_offset + CCSDS_TM_OCF_LEN + CCSDS_TM_FECF_LEN ==
                    CCSDS_TM_FRAME_LEN);

    increment_frame_counters(vcid);
    *frame_len = CCSDS_TM_FRAME_LEN;
    ret = 0;

out_unlock:
    k_mutex_unlock(&vc->write_lock);

    return ret;
}

static size_t code_transfer_frame(const uint8_t *frame, size_t frame_len)
{
#ifdef CONFIG_AKIRA_CCSDS_RS
    uint8_t *parity = &coded_frame_buf[CCSDS_TM_ASM_LEN + frame_len];

    __ASSERT_NO_MSG(frame_len == CCSDS_RS_INTERLEAVED_DATA_LEN);

    coded_frame_buf[0] = CCSDS_TM_ASM0;
    coded_frame_buf[1] = CCSDS_TM_ASM1;
    coded_frame_buf[2] = CCSDS_TM_ASM2;
    coded_frame_buf[3] = CCSDS_TM_ASM3;
    memcpy(&coded_frame_buf[CCSDS_TM_ASM_LEN], frame, frame_len);
    ccsds_rs_encode(frame, parity);

    return CCSDS_TM_CODED_FRAME_LEN;
#else
    coded_frame_buf[0] = CCSDS_TM_ASM0;
    coded_frame_buf[1] = CCSDS_TM_ASM1;
    coded_frame_buf[2] = CCSDS_TM_ASM2;
    coded_frame_buf[3] = CCSDS_TM_ASM3;
    memcpy(&coded_frame_buf[CCSDS_TM_ASM_LEN], frame, frame_len);

    return CCSDS_TM_ASM_LEN + frame_len;
#endif
}

static bool vc_has_pending_bytes(uint8_t vcid)
{
    struct ccsds_tm_vc *vc = &vcs[vcid];
    bool has_pending;

    k_mutex_lock(&vc->write_lock, K_FOREVER);
    has_pending = vc->pending_len > 0u || vc->packet_rem > 0u;
    k_mutex_unlock(&vc->write_lock);

    return has_pending;
}

static bool generator_select_active_vc(uint8_t *vcid)
{
    for (uint8_t i = 0u; i < ARRAY_SIZE(vcs); i++) {
        if (vc_has_pending_bytes(i)) {
            *vcid = i;
            return true;
        }
    }

    return false;
}

static bool generator_cycle(void)
{
    uint8_t vcid = 0u;
    bool active = generator_select_active_vc(&vcid);

    generator_last_cycle_active = active;
    generator_last_vcid = active ? vcid : CCSDS_TM_IDLE_VC_ID;

    if (!active) {
        size_t frame_len = build_idle_transfer_frame(CCSDS_TM_IDLE_VC_ID);
        size_t coded_len = code_transfer_frame(frame_buf, frame_len);

        route_frame(CCSDS_TM_IDLE_VC_ID, coded_frame_buf, coded_len);
    } else {
        size_t frame_len;

        if (build_packet_transfer_frame(vcid, &frame_len) == 0) {
            size_t coded_len = code_transfer_frame(frame_buf, frame_len);

            route_frame(vcid, coded_frame_buf, coded_len);
        }
    }

    return active;
}

static void generator_work_handler(struct k_work *work)
{
    bool active;
    bool running;
    k_timeout_t next_delay;

    ARG_UNUSED(work);

    k_mutex_lock(&generator_lock, K_FOREVER);
    running = generator_running;
    k_mutex_unlock(&generator_lock);

    if (!running) {
        return;
    }

    active = generator_cycle();

    k_mutex_lock(&generator_lock, K_FOREVER);
    running = generator_running;
    next_delay = active ? generator_active_delay : generator_idle_delay;
    k_mutex_unlock(&generator_lock);

    if (running) {
        (void)k_work_schedule(&generator_work, next_delay);
    }
}

static void generator_init_once(void)
{
    if (generator_work_initialized) {
        return;
    }

    k_mutex_init(&generator_lock);
    k_work_init_delayable(&generator_work, generator_work_handler);
    generator_work_initialized = true;
}

/* Dispatch a complete TM frame through the callbacks selected by its VC mask. */
static __maybe_unused void route_frame(uint8_t vcid, const uint8_t *frame,
                                       size_t frame_len)
{
    ccsds_tm_route_mask_t route_mask;

    __ASSERT(initialized, "ccsds_tm_frame_init() not called");
    __ASSERT(vcid <= CCSDS_TM_MAX_VC_ID, "invalid TM VCID");
    __ASSERT(frame != NULL, "TM frame is NULL");

    route_mask = vcs[vcid].route_mask;

    for (uint8_t bit_num = 0u;
         route_mask != CCSDS_TM_ROUTE_NONE && bit_num < ARRAY_SIZE(routes);
         bit_num++) {
        ccsds_tm_route_mask_t route_bit = (ccsds_tm_route_mask_t)BIT(bit_num);
        struct ccsds_tm_route *route = &routes[bit_num];

        if ((route_mask & route_bit) == 0u) {
            continue;
        }

        route_mask &= ~route_bit;

        if (route->fn != NULL) {
            (void)route->fn(vcid, frame, frame_len, route->user_data);
        }
    }
}

/* Reset TM VC queues, frame counters, and all route registration state. */
int ccsds_tm_frame_init(void)
{
    generator_init_once();

    (void)ccsds_tm_frame_stop();

    for (size_t i = 0u; i < ARRAY_SIZE(vcs); i++) {
        vcs[i].pending_len = 0u;
        vcs[i].packet_rem = 0u;
        vcs[i].packet_is_idle = false;
        vcs[i].vcfc = 0u;
        vcs[i].route_mask = CCSDS_TM_ROUTE_NONE;

        k_mutex_init(&vcs[i].write_lock);
        k_pipe_init(&vcs[i].pending, vcs[i].pending_storage,
                    sizeof(vcs[i].pending_storage));
    }

    memset(routes, 0, sizeof(routes));
    memset(&clcw_provider, 0, sizeof(clcw_provider));
    memset(frame_buf, 0, sizeof(frame_buf));
    mcfc = 0u;
    generator_active_delay = K_NO_WAIT;
    generator_idle_delay = K_NO_WAIT;
    generator_last_vcid = CCSDS_TM_MAX_VC_ID;
    generator_last_cycle_active = false;
    initialized = true;

    return 0;
}

/* Register one callback in the route table for a single supported route bit. */
int ccsds_tm_frame_register_route(ccsds_tm_route_mask_t route_bit,
                                  ccsds_tm_route_fn_t fn, void *user_data)
{
    uint8_t bit_num;

    if (!route_bit_is_valid(route_bit)) {
        return -EINVAL;
    }

    __ASSERT(fn != NULL, "TM route callback is NULL");
    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    bit_num = route_bit_index(route_bit);
    routes[bit_num].fn = fn;
    routes[bit_num].user_data = user_data;

    return 0;
}

int ccsds_tm_frame_set_clcw_provider(ccsds_tm_clcw_provider_t fn,
                                     void *user_data)
{
    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    clcw_provider.fn = fn;
    clcw_provider.user_data = user_data;

    return 0;
}

/* Store the route mask that future generated frames for a VC will use. */
int ccsds_tm_frame_set_vc_route(uint8_t vcid, ccsds_tm_route_mask_t route_mask)
{
    if (vcid > CCSDS_TM_MAX_VC_ID || !route_mask_is_valid(route_mask)) {
        return -EINVAL;
    }

    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    vcs[vcid].route_mask = route_mask;

    return 0;
}

/* Read the current route mask for shell/status reporting and tests. */
int ccsds_tm_frame_get_vc_route(uint8_t vcid,
                                ccsds_tm_route_mask_t *route_mask)
{
    if (vcid > CCSDS_TM_MAX_VC_ID) {
        return -EINVAL;
    }

    __ASSERT(route_mask != NULL, "TM route output mask is NULL");
    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    *route_mask = vcs[vcid].route_mask;

    return 0;
}

int ccsds_tm_frame_start(k_timeout_t active_delay, k_timeout_t idle_delay)
{
    generator_init_once();

    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    k_mutex_lock(&generator_lock, K_FOREVER);
    generator_active_delay = active_delay;
    generator_idle_delay = idle_delay;
    generator_running = true;
    k_mutex_unlock(&generator_lock);

    (void)k_work_schedule(&generator_work, K_NO_WAIT);

    return 0;
}

int ccsds_tm_frame_stop(void)
{
    generator_init_once();

    k_mutex_lock(&generator_lock, K_FOREVER);
    generator_running = false;
    k_mutex_unlock(&generator_lock);

    (void)k_work_cancel_delayable(&generator_work);

    return 0;
}

#ifdef CONFIG_ZTEST
bool ccsds_tm_frame_test_is_running(void)
{
    bool running;

    generator_init_once();

    k_mutex_lock(&generator_lock, K_FOREVER);
    running = generator_running;
    k_mutex_unlock(&generator_lock);

    return running;
}

bool ccsds_tm_frame_test_run_cycle(k_timeout_t *next_delay, uint8_t *vcid)
{
    bool active;

    active = generator_cycle();

    if (next_delay != NULL) {
        *next_delay = active ? generator_active_delay : generator_idle_delay;
    }

    if (vcid != NULL) {
        *vcid = generator_last_vcid;
    }

    return active;
}

int ccsds_tm_frame_test_get_clcw(uint32_t *clcw)
{
    if (clcw_provider.fn == NULL) {
        return -ENOENT;
    }

    return clcw_provider.fn(clcw, clcw_provider.user_data);
}
#endif /* CONFIG_ZTEST */

/* Validate and enqueue one complete encoded Space Packet for the selected VC. */
int ccsds_tm_frame_add(uint8_t vcid, const uint8_t *packet, size_t packet_len,
                       k_timeout_t timeout)
{
    struct ccsds_tm_vc *vc;
    size_t written = 0u;
    int ret;

    __ASSERT(packet != NULL, "TM input packet is NULL");

    if (packet_len < CCSDS_SPACE_PACKET_MIN_LEN) {
        return -EINVAL;
    }

    if (packet_total_len(packet) != packet_len) {
        return -EINVAL;
    }

    if (packet_len > CONFIG_AKIRA_CCSDS_TM_MAX_SPACE_PACKET_LEN) {
        return -EMSGSIZE;
    }

    if (packet_len > CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH) {
        return -EMSGSIZE;
    }

    if (vcid > CCSDS_TM_MAX_VC_ID) {
        return -EINVAL;
    }

    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    vc = &vcs[vcid];

    ret = k_mutex_lock(&vc->write_lock, timeout);
    if (ret != 0) {
        return ret;
    }

    while (written < packet_len) {
        ret = k_pipe_write(&vc->pending, &packet[written],
                           packet_len - written, timeout);
        if (ret < 0) {
            goto out_unlock;
        }
        __ASSERT(ret > 0, "k_pipe_write() made no progress");
        if (ret == 0) {
            ret = -EIO;
            goto out_unlock;
        }

        written += (size_t)ret;
        vc->pending_len += (size_t)ret;
    }

    ret = 0;

out_unlock:
    k_mutex_unlock(&vc->write_lock);

    return ret;
}
