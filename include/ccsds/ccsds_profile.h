/**
 * @file ccsds_profile.h
 * @brief Optional CCSDS layer-composition helpers.
 */

#ifndef AKIRA_CCSDS_PROFILE_H
#define AKIRA_CCSDS_PROFILE_H

#include "ccsds_cltu.h"
#include "ccsds_router.h"
#include "ccsds_tc_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_profile_rf_tc {
    struct ccsds_cltu_rx cltu_rx;
    struct ccsds_router *router;
    uint8_t frame_buf[CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN];
};

int ccsds_profile_rf_tc_init(struct ccsds_profile_rf_tc *profile,
                             struct ccsds_router *router);

int ccsds_profile_rf_tc_push(struct ccsds_profile_rf_tc *profile,
                             const uint8_t *bytes, size_t len);

int ccsds_profile_packet_dispatch(struct ccsds_router *router,
                                  const uint8_t *packet, size_t packet_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_PROFILE_H */
