#include "ccsds_profile.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(ccsds_profile, CONFIG_AKIRA_LOG_LEVEL);

static K_MUTEX_DEFINE(tc_rx_stats_lock);
static struct ccsds_profile_tc_rx_stats tc_rx_stats;

enum ccsds_profile_tc_cltu_stage {
    CCSDS_PROFILE_TC_CLTU_STAGE_NONE,
    CCSDS_PROFILE_TC_CLTU_STAGE_OVERSIZE,
    CCSDS_PROFILE_TC_CLTU_STAGE_CLTU,
    CCSDS_PROFILE_TC_CLTU_STAGE_TC_FRAME,
    CCSDS_PROFILE_TC_CLTU_STAGE_CONTROL,
    CCSDS_PROFILE_TC_CLTU_STAGE_PACKET,
    CCSDS_PROFILE_TC_CLTU_STAGE_ROUTER,
    CCSDS_PROFILE_TC_CLTU_STAGE_DISPATCHED,
};

struct ccsds_profile_tc_cltu_result {
    enum ccsds_profile_tc_cltu_stage stage;
    int error;
    size_t tc_frame_len;
};

static void init_tc_result(struct ccsds_profile_tc_cltu_result *result)
{
    if (result) {
        memset(result, 0, sizeof(*result));
        result->stage = CCSDS_PROFILE_TC_CLTU_STAGE_NONE;
    }
}

static void set_tc_result_error(struct ccsds_profile_tc_cltu_result *result,
                                enum ccsds_profile_tc_cltu_stage stage,
                                int error)
{
    if (result) {
        result->stage = stage;
        result->error = error;
    }
}

static void record_tc_result(const struct ccsds_profile_tc_cltu_result *result,
                             size_t cltu_len, int ret)
{
    k_mutex_lock(&tc_rx_stats_lock, K_FOREVER);
    tc_rx_stats.cltus_received++;
    tc_rx_stats.last_cltu_len = cltu_len;
    tc_rx_stats.last_tc_frame_len = result->tc_frame_len;

    switch (result->stage) {
    case CCSDS_PROFILE_TC_CLTU_STAGE_OVERSIZE:
        tc_rx_stats.cltus_oversize++;
        break;
    case CCSDS_PROFILE_TC_CLTU_STAGE_CLTU:
        tc_rx_stats.cltu_decode_failures++;
        break;
    case CCSDS_PROFILE_TC_CLTU_STAGE_TC_FRAME:
    case CCSDS_PROFILE_TC_CLTU_STAGE_PACKET:
        tc_rx_stats.tc_frame_rejects++;
        break;
    case CCSDS_PROFILE_TC_CLTU_STAGE_CONTROL:
        tc_rx_stats.control_frames_seen++;
        break;
    case CCSDS_PROFILE_TC_CLTU_STAGE_ROUTER:
        tc_rx_stats.dispatch_failures++;
        break;
    case CCSDS_PROFILE_TC_CLTU_STAGE_DISPATCHED:
        tc_rx_stats.packets_dispatched++;
        break;
    case CCSDS_PROFILE_TC_CLTU_STAGE_NONE:
    default:
        tc_rx_stats.dispatch_failures++;
        break;
    }

    if (ret != 0) {
        tc_rx_stats.last_error = ret;
    }

    k_mutex_unlock(&tc_rx_stats_lock);
}

int ccsds_profile_tc_rx_init(struct ccsds_profile_tc_rx *profile,
                             struct ccsds_router *router)
{
    if (!profile || !router) {
        return -EINVAL;
    }

    memset(profile, 0, sizeof(*profile));
    profile->router = router;

    return 0;
}

int ccsds_profile_tc_cltu_dispatch(struct ccsds_profile_tc_rx *profile,
                                   const uint8_t *cltu, size_t cltu_len)
{
    struct ccsds_profile_tc_cltu_result result;
    struct ccsds_tc_frame frame;
    struct ccsds_space_packet packet;
    size_t tc_frame_len = 0u;
    int ret;

    init_tc_result(&result);

    if (!profile || !profile->router || !cltu) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_NONE,
                            -EINVAL);
        record_tc_result(&result, cltu_len, -EINVAL);
        return -EINVAL;
    }

    if (cltu_len > CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_OVERSIZE,
                            -EMSGSIZE);
        record_tc_result(&result, cltu_len, -EMSGSIZE);
        return -EMSGSIZE;
    }

    ret = ccsds_cltu_decode_message(cltu, cltu_len, profile->frame_buf,
                                    sizeof(profile->frame_buf), &tc_frame_len);
    result.tc_frame_len = tc_frame_len;
    if (ret != 0) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_CLTU, ret);
        record_tc_result(&result, cltu_len, ret);
        return ret;
    }

    ret = ccsds_tc_frame_decode(profile->frame_buf, tc_frame_len, &frame);
    if (ret != 0) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_TC_FRAME,
                            ret);
        record_tc_result(&result, cltu_len, ret);
        return ret;
    }

    LOG_INF("TC frame received: cltu_len=%zu decoded_len=%zu scid=%u vcid=%u "
            "bypass=%u control=%u fsn=%u data_len=%zu",
            cltu_len, tc_frame_len, frame.spacecraft_id,
            frame.virtual_channel_id, frame.bypass ? 1u : 0u,
            frame.control_command ? 1u : 0u, frame.frame_sequence_number,
            frame.data_len);

    if (frame.control_command) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_CONTROL,
                            -ENOTSUP);
        record_tc_result(&result, cltu_len, -ENOTSUP);
        return -ENOTSUP;
    }

    ret = ccsds_tc_frame_extract_packet(&frame, &packet);
    if (ret != 0) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_PACKET, ret);
        record_tc_result(&result, cltu_len, ret);
        return ret;
    }

    ret = ccsds_router_dispatch(profile->router, &packet);
    if (ret != 0) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_ROUTER, ret);
        record_tc_result(&result, cltu_len, ret);
        return ret;
    }

    result.stage = CCSDS_PROFILE_TC_CLTU_STAGE_DISPATCHED;
    result.error = 0;
    record_tc_result(&result, cltu_len, 0);

    return 0;
}

void ccsds_profile_tc_rx_get_stats(struct ccsds_profile_tc_rx_stats *stats)
{
    if (!stats) {
        return;
    }

    k_mutex_lock(&tc_rx_stats_lock, K_FOREVER);
    *stats = tc_rx_stats;
    k_mutex_unlock(&tc_rx_stats_lock);
}

void ccsds_profile_tc_rx_reset_stats(void)
{
    k_mutex_lock(&tc_rx_stats_lock, K_FOREVER);
    memset(&tc_rx_stats, 0, sizeof(tc_rx_stats));
    k_mutex_unlock(&tc_rx_stats_lock);
}

int ccsds_profile_packet_dispatch(struct ccsds_router *router,
                                  const uint8_t *packet, size_t packet_len)
{
    return ccsds_router_dispatch_bytes(router, packet, packet_len);
}
