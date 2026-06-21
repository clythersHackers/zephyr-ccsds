#include "ccsds_profile.h"

#include <errno.h>
#include <string.h>

static int on_rf_tc_frame(const uint8_t *tc_frame, size_t tc_frame_len,
                          void *user_data)
{
    struct ccsds_profile_rf_tc *profile = user_data;
    struct ccsds_tc_frame frame;
    struct ccsds_space_packet packet;
    int ret;

    ret = ccsds_tc_frame_decode(tc_frame, tc_frame_len, &frame);
    if (ret != 0) {
        return ret;
    }

    ret = ccsds_tc_frame_extract_packet(&frame, &packet);
    if (ret != 0) {
        return ret;
    }

    return ccsds_router_dispatch(profile->router, &packet);
}

int ccsds_profile_rf_tc_init(struct ccsds_profile_rf_tc *profile,
                             struct ccsds_router *router)
{
    if (!profile || !router) {
        return -EINVAL;
    }

    memset(profile, 0, sizeof(*profile));
    profile->router = router;
    return ccsds_cltu_rx_init(&profile->cltu_rx, on_rf_tc_frame, profile);
}

int ccsds_profile_rf_tc_push(struct ccsds_profile_rf_tc *profile,
                             const uint8_t *bytes, size_t len)
{
    if (!profile) {
        return -EINVAL;
    }

    return ccsds_cltu_rx_push(&profile->cltu_rx, bytes, len);
}

int ccsds_profile_packet_dispatch(struct ccsds_router *router,
                                  const uint8_t *packet, size_t packet_len)
{
    return ccsds_router_dispatch_bytes(router, packet, packet_len);
}
