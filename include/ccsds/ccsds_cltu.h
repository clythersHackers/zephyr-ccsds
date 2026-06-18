/**
 * @file ccsds_cltu.h
 * @brief CCSDS CLTU acquisition and decode boundary.
 */

#ifndef AKIRA_CCSDS_CLTU_H
#define AKIRA_CCSDS_CLTU_H

#include "ccsds_bch.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*ccsds_cltu_frame_cb_t)(const uint8_t *tc_frame,
                                     size_t tc_frame_len,
                                     void *user_data);

struct ccsds_cltu_rx_config {
    const uint8_t *start_sequence;
    size_t start_sequence_len;
    const uint8_t *tail_sequence;
    size_t tail_sequence_len;
    bool bch_correction;
};

struct ccsds_cltu_rx {
    struct ccsds_cltu_rx_config cfg;
    ccsds_cltu_frame_cb_t on_frame;
    void *user_data;
    size_t buffered_len;
    bool in_cltu;
    uint8_t buffer[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
};

int ccsds_cltu_rx_init(struct ccsds_cltu_rx *rx,
                       const struct ccsds_cltu_rx_config *cfg,
                       ccsds_cltu_frame_cb_t on_frame,
                       void *user_data);

void ccsds_cltu_rx_reset(struct ccsds_cltu_rx *rx);

int ccsds_cltu_rx_push(struct ccsds_cltu_rx *rx, const uint8_t *chunk,
                       size_t chunk_len);

int ccsds_cltu_decode_message(const uint8_t *cltu, size_t cltu_len,
                              uint8_t *tc_frame, size_t tc_frame_cap,
                              size_t *tc_frame_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CLTU_H */
