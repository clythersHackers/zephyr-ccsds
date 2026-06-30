#include "ccsds_profile.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(ccsds_profile, CONFIG_AKIRA_LOG_LEVEL);

#define CCSDS_TC_CONTROL_UNLOCK 0x00u
#define CCSDS_TC_CONTROL_SET_VR 0x82u
#define CCSDS_TC_CONTROL_SET_VR_QUALIFIER 0x00u
#define CCSDS_TC_CONTROL_SET_VR_MIN_LEN 3u
#define CCSDS_CLCW_CONTROL_WORD_TYPE 0u
#define CCSDS_CLCW_VERSION_NUMBER 0u
#define CCSDS_CLCW_STATUS_FIELD 0u
#define CCSDS_CLCW_COP_IN_EFFECT 1u
#define CCSDS_TC_FSN_MODULO 256u
#define CCSDS_TC_COP1_HALF_WINDOW (CONFIG_AKIRA_CCSDS_COP1_WINDOW_SIZE / 2u)

BUILD_ASSERT(CONFIG_AKIRA_CCSDS_COP1_WINDOW_SIZE >= 4,
             "COP-1 window size must leave a non-empty positive/negative window");
BUILD_ASSERT(CONFIG_AKIRA_CCSDS_COP1_WINDOW_SIZE <= CCSDS_TC_FSN_MODULO / 2u,
             "COP-1 window size must fit inside the 8-bit FSN half range");

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
    __ASSERT(result != NULL, "TC CLTU result is NULL");

    memset(result, 0, sizeof(*result));
    result->stage = CCSDS_PROFILE_TC_CLTU_STAGE_NONE;
}

static void set_tc_result_error(struct ccsds_profile_tc_cltu_result *result,
                                enum ccsds_profile_tc_cltu_stage stage,
                                int error)
{
    __ASSERT(result != NULL, "TC CLTU result is NULL");

    result->stage = stage;
    result->error = error;
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

static int validate_tc_vcid(const struct ccsds_profile_tc_rx *profile,
                            const struct ccsds_tc_frame *frame)
{
    uint8_t vcid;

    __ASSERT(profile != NULL, "TC profile is NULL");
    __ASSERT(frame != NULL, "TC frame is NULL");

    if (frame->virtual_channel_id >= CCSDS_TC_VC_COUNT) {
        return -EINVAL;
    }

    vcid = frame->virtual_channel_id;
    if (vcid != profile->accepted_vcid) {
        LOG_WRN("TC frame rejected for unconfigured VC: vcid=%u accepted=%u",
                vcid, profile->accepted_vcid);
        return -EACCES;
    }

    return 0;
}

static int handle_tc_control_frame(struct ccsds_profile_tc_rx *profile,
                                   const struct ccsds_tc_frame *frame)
{
    uint8_t vcid;

    __ASSERT(profile != NULL, "TC profile is NULL");
    __ASSERT(frame != NULL, "TC frame is NULL");
    __ASSERT(frame->data != NULL, "TC control frame data is NULL");

    if (frame->data_len == 0u) {
        return -EINVAL;
    }

    vcid = frame->virtual_channel_id;

    if (frame->data[0] == CCSDS_TC_CONTROL_UNLOCK) {
        profile->vc_state.lockout_flag = false;
        profile->vc_state.retransmit_flag = false;
        LOG_INF("TC control UNLOCK: vcid=%u", vcid);
        return 0;
    }

    if (frame->data_len >= CCSDS_TC_CONTROL_SET_VR_MIN_LEN &&
        frame->data[0] == CCSDS_TC_CONTROL_SET_VR &&
        frame->data[1] == CCSDS_TC_CONTROL_SET_VR_QUALIFIER) {
        profile->vc_state.report_value = frame->data[2];
        profile->vc_state.retransmit_flag = false;
        LOG_INF("TC control SET VR: vcid=%u report_value=%u", vcid,
                profile->vc_state.report_value);
        return 0;
    }

    LOG_WRN("TC control command unsupported: vcid=%u first=0x%02x len=%zu",
            vcid, frame->data[0], frame->data_len);
    return -ENOTSUP;
}

static int update_tc_sequence_state(struct ccsds_profile_tc_rx *profile,
                                    const struct ccsds_tc_frame *frame)
{
    uint8_t expected_fsn;
    uint8_t received_fsn;

    __ASSERT(profile != NULL, "TC profile is NULL");
    __ASSERT(frame != NULL, "TC frame is NULL");

    if (frame->bypass || frame->control_command) {
        return 0;
    }

    expected_fsn = profile->vc_state.report_value;
    received_fsn = frame->frame_sequence_number;

    if (received_fsn == expected_fsn) {
        profile->vc_state.report_value = (uint8_t)(expected_fsn + 1u);
        profile->vc_state.retransmit_flag = false;

        return 0;
    }

    if ((uint8_t)(expected_fsn - received_fsn) < (uint8_t)CCSDS_TC_COP1_HALF_WINDOW) {
        LOG_WRN("TC frame sequence duplicate: vcid=%u expected=%u received=%u",
                frame->virtual_channel_id, expected_fsn, received_fsn);
        return -EAGAIN;
    }

    if ((uint8_t)(received_fsn - expected_fsn) < (uint8_t)CCSDS_TC_COP1_HALF_WINDOW) {
        profile->vc_state.retransmit_flag = true;
        LOG_WRN("TC frame sequence jump: vcid=%u expected=%u received=%u",
                frame->virtual_channel_id, expected_fsn, received_fsn);
        return -EAGAIN;
    }

    profile->vc_state.lockout_flag = true;
    LOG_WRN("TC frame sequence lockout: vcid=%u expected=%u received=%u",
            frame->virtual_channel_id, expected_fsn, received_fsn);

    return -EAGAIN;
}

int ccsds_profile_tc_build_clcw(const struct ccsds_profile_tc_rx *profile,
                                uint32_t *clcw)
{
    const struct ccsds_profile_tc_vc_state *state;

    __ASSERT(profile != NULL, "TC profile is NULL");
    __ASSERT(clcw != NULL, "CLCW output is NULL");

    if (profile->accepted_vcid >= CCSDS_TC_VC_COUNT) {
        return -EINVAL;
    }

    state = &profile->vc_state;

    *clcw = ((uint32_t)(CCSDS_CLCW_CONTROL_WORD_TYPE & 0x1u) << 31) |
            ((uint32_t)(CCSDS_CLCW_VERSION_NUMBER & 0x3u) << 29) |
            ((uint32_t)(CCSDS_CLCW_STATUS_FIELD & 0x7u) << 26) |
            ((uint32_t)(CCSDS_CLCW_COP_IN_EFFECT & 0x3u) << 24) |
            ((uint32_t)(profile->accepted_vcid & 0x3fu) << 18) |
            ((uint32_t)(state->no_rf_available_flag ? 1u : 0u) << 15) |
            ((uint32_t)(state->no_bit_lock_flag ? 1u : 0u) << 14) |
            ((uint32_t)(state->lockout_flag ? 1u : 0u) << 13) |
            ((uint32_t)(state->wait_flag ? 1u : 0u) << 12) |
            ((uint32_t)(state->retransmit_flag ? 1u : 0u) << 11) |
            ((uint32_t)(state->farm_b_counter & 0x3u) << 9) |
            state->report_value;

    return 0;
}

int ccsds_profile_tc_clcw_provider(uint32_t *clcw, void *user_data)
{
    struct ccsds_profile_tc_rx *profile = user_data;

    __ASSERT(profile != NULL, "TC profile CLCW provider data is NULL");

    return ccsds_profile_tc_build_clcw(profile, clcw);
}

int ccsds_profile_tc_rx_init(struct ccsds_profile_tc_rx *profile,
                             struct ccsds_router *router)
{
    __ASSERT(profile != NULL, "TC profile is NULL");
    __ASSERT(router != NULL, "TC profile router is NULL");

    memset(profile, 0, sizeof(*profile));
    profile->router = router;

    return 0;
}

int ccsds_profile_tc_set_accepted_vcid(struct ccsds_profile_tc_rx *profile,
                                       uint8_t tc_vcid)
{
    __ASSERT(profile != NULL, "TC profile is NULL");

    if (tc_vcid >= CCSDS_TC_VC_COUNT) {
        return -EINVAL;
    }

    profile->accepted_vcid = tc_vcid;

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

    __ASSERT(profile != NULL, "TC profile is NULL");
    __ASSERT(profile->router != NULL, "TC profile router is NULL");
    __ASSERT(cltu != NULL, "TC CLTU input is NULL");

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

    ret = validate_tc_vcid(profile, &frame);
    if (ret != 0) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_TC_FRAME,
                            ret);
        record_tc_result(&result, cltu_len, ret);
        return ret;
    }

    if (frame.control_command) {
        ret = handle_tc_control_frame(profile, &frame);
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_CONTROL, ret);
        record_tc_result(&result, cltu_len, ret);
        return ret;
    }

    ret = update_tc_sequence_state(profile, &frame);
    if (ret != 0) {
        set_tc_result_error(&result, CCSDS_PROFILE_TC_CLTU_STAGE_TC_FRAME,
                            ret);
        record_tc_result(&result, cltu_len, ret);
        return ret;
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
    __ASSERT(stats != NULL, "TC RX stats output is NULL");

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
