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

/**
 * @brief Initialize an RF telecommand CLTU-to-router profile.
 *
 * @param profile Profile instance to initialize.
 * @param router Router used after CLTU and TC frame decoding.
 *
 * @return 0 on success, or -EINVAL for invalid input.
 */
int ccsds_profile_rf_tc_init(struct ccsds_profile_rf_tc *profile,
                             struct ccsds_router *router);

/**
 * @brief Feed RF telecommand bytes into a profile receiver.
 *
 * @param profile Initialized RF telecommand profile.
 * @param bytes Incoming transport bytes.
 * @param len Length of @p bytes in bytes.
 *
 * @return 0 on success, -EINVAL for invalid input, or a lower-layer CLTU,
 *         TC frame, Space Packet, or router error.
 */
int ccsds_profile_rf_tc_push(struct ccsds_profile_rf_tc *profile,
                             const uint8_t *bytes, size_t len);

/**
 * @brief Decode encoded Space Packet bytes and dispatch them through a router.
 *
 * @param router Router used to select an APID handler.
 * @param packet Encoded CCSDS Space Packet.
 * @param packet_len Length of @p packet in bytes.
 *
 * @return Handler return value on match, a decode error, or a router error.
 */
int ccsds_profile_packet_dispatch(struct ccsds_router *router,
                                  const uint8_t *packet, size_t packet_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_PROFILE_H */
