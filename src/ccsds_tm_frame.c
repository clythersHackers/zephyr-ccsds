#include "ccsds_tm_frame.h"

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>

#define CCSDS_TM_MAX_VC_ID 7u
#define CCSDS_TM_VC_COUNT (CCSDS_TM_MAX_VC_ID + 1u)
#define CCSDS_TM_ROUTE_COUNT 32u
#define CCSDS_SPACE_PACKET_MIN_LEN (CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + 1u)

struct ccsds_tm_vc {
    struct k_mutex write_lock;
    struct k_pipe pending;
    uint8_t pending_storage[CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH];

    uint16_t packet_rem;
    bool packet_is_idle;

    uint8_t vcfc;
    ccsds_tm_route_mask_t route_mask;
};

struct ccsds_tm_route {
    ccsds_tm_route_fn_t fn;
    void *user_data;
};

static struct ccsds_tm_vc vcs[CCSDS_TM_VC_COUNT];
static struct ccsds_tm_route routes[CCSDS_TM_ROUTE_COUNT];
static uint8_t frame_buf[CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN];
static uint8_t mcfc;
static bool initialized;

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
    for (size_t i = 0u; i < ARRAY_SIZE(vcs); i++) {
        vcs[i].packet_rem = 0u;
        vcs[i].packet_is_idle = false;
        vcs[i].vcfc = 0u;
        vcs[i].route_mask = CCSDS_TM_ROUTE_NONE;

        k_mutex_init(&vcs[i].write_lock);
        k_pipe_init(&vcs[i].pending, vcs[i].pending_storage,
                    sizeof(vcs[i].pending_storage));
    }

    memset(routes, 0, sizeof(routes));
    memset(frame_buf, 0, sizeof(frame_buf));
    mcfc = 0u;
    initialized = true;

    return 0;
}

/* Register one callback in the route table for a single supported route bit. */
int ccsds_tm_frame_register_route(ccsds_tm_route_mask_t route_bit,
                                  ccsds_tm_route_fn_t fn, void *user_data)
{
    uint8_t bit_num;

    if (!route_bit_is_valid(route_bit) || fn == NULL) {
        return -EINVAL;
    }

    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    bit_num = route_bit_index(route_bit);
    routes[bit_num].fn = fn;
    routes[bit_num].user_data = user_data;

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

/* Validate and enqueue one complete encoded Space Packet for the selected VC. */
int ccsds_tm_frame_add(uint8_t vcid, const uint8_t *packet, size_t packet_len,
                       k_timeout_t timeout)
{
    struct ccsds_tm_vc *vc;
    size_t written = 0u;
    int ret;

    if (!packet || packet_len < CCSDS_SPACE_PACKET_MIN_LEN) {
        return -EINVAL;
    }

    if (packet_total_len(packet) != packet_len) {
        return -EINVAL;
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
    }

    ret = 0;

out_unlock:
    k_mutex_unlock(&vc->write_lock);

    return ret;
}
