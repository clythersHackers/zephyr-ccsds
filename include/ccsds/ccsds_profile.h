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

struct ccsds_profile_tc_vc_state {
    bool no_rf_available_flag;
    bool no_bit_lock_flag;
    bool wait_flag;
    bool lockout_flag;
    bool retransmit_flag;
    uint8_t farm_b_counter;
    /* CLCW report value: next expected TC frame sequence number V(R). */
    uint8_t report_value;
};

struct ccsds_profile_tc_rx {
    struct ccsds_router *router;
    uint8_t accepted_vcid;
    struct ccsds_profile_tc_vc_state vc_state;
    uint8_t frame_buf[CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN];
};

struct ccsds_profile_tc_rx_stats {
    uint32_t cltus_received;
    uint32_t cltus_oversize;
    uint32_t cltu_decode_failures;
    uint32_t tc_frame_rejects;
    uint32_t control_frames_seen;
    uint32_t packets_dispatched;
    uint32_t dispatch_failures;
    int last_error;
    size_t last_cltu_len;
    size_t last_tc_frame_len;
};

/**
 * @brief Initialize a generic telecommand receive profile.
 *
 * This profile owns TC receive state after a complete CLTU has been acquired,
 * including the decoded TC transfer-frame workspace. Input adapters should
 * keep only their transport state and pass complete CLTUs into this profile.
 *
 * @param profile Profile instance to initialize.
 * @param router Router used after TC frame decode and packet extraction.
 *
 * @return 0 on success, or -EINVAL for invalid input.
 */
int ccsds_profile_tc_rx_init(struct ccsds_profile_tc_rx *profile,
                             struct ccsds_router *router);

/**
 * @brief Decode one complete TC CLTU and dispatch its Space Packet by APID.
 *
 * @param profile Generic TC receive profile.
 * @param cltu Complete CLTU bytes.
 * @param cltu_len Length of @p cltu in bytes.
 *
 * @return 0 on successful APID dispatch or recognized TC control frame
 *         handling, -ENOTSUP for unknown TC control commands, or a lower-layer
 *         decode/router error.
 */
int ccsds_profile_tc_cltu_dispatch(struct ccsds_profile_tc_rx *profile,
                                   const uint8_t *cltu, size_t cltu_len);

/**
 * @brief Configure the single TC virtual channel accepted by this profile.
 *
 * AkiraOS currently models one spacecraft-side TC receive endpoint. Frames
 * for other TC VCs are rejected, and the CLCW reports this configured VC.
 *
 * @param profile Generic TC receive profile.
 * @param tc_vcid TC virtual channel ID, 0 through 63.
 *
 * @return 0 on success, or -EINVAL for invalid input.
 */
int ccsds_profile_tc_set_accepted_vcid(struct ccsds_profile_tc_rx *profile,
                                       uint8_t tc_vcid);

/**
 * @brief Copy aggregate TC receive counters shared by all complete-CLTU inputs.
 *
 * @param stats Output snapshot. Ignored when NULL.
 */
void ccsds_profile_tc_rx_get_stats(struct ccsds_profile_tc_rx_stats *stats);

/**
 * @brief Clear aggregate TC receive counters.
 */
void ccsds_profile_tc_rx_reset_stats(void);

/**
 * @brief Build a CLCW from this profile's configured TC receive state.
 *
 * @param profile Generic TC receive profile.
 * @param clcw Output encoded CLCW word in host integer form.
 *
 * @return 0 on success, or -EINVAL for invalid input.
 */
int ccsds_profile_tc_build_clcw(const struct ccsds_profile_tc_rx *profile,
                                uint32_t *clcw);

/**
 * @brief TM CLCW provider callback backed by struct ccsds_profile_tc_rx.
 *
 * @param clcw Output encoded CLCW word in host integer form.
 * @param user_data Pointer to struct ccsds_profile_tc_rx.
 *
 * @return 0 on success, or -EINVAL for invalid input.
 */
int ccsds_profile_tc_clcw_provider(uint32_t *clcw, void *user_data);

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
