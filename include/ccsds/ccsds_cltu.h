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

#define CLTU_START_SEQUENCE 0xeb90u

typedef int (*ccsds_cltu_frame_cb_t)(const uint8_t *tc_frame,
                                     size_t tc_frame_len,
                                     void *user_data);

struct ccsds_cltu_rx {
    ccsds_cltu_frame_cb_t on_frame;
    void *user_data;
    size_t buffered_len;
    bool in_cltu;
    uint8_t buffer[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
};

/**
 * Return true when @p candidate points to a valid CLTU start sequence.
 *
 * The nominal start sequence is 0xEB90. CCSDS acquisition tolerates one bit
 * error in this marker, so this helper accepts two-byte big-endian candidates
 * with Hamming distance 0 or 1 from CLTU_START_SEQUENCE.
 */
static inline bool ccsds_cltu_is_start_sequence(const uint8_t *candidate)
{
    unsigned int errors;

    if (!candidate) {
        return false;
    }

    errors = __builtin_popcount(candidate[0] ^ (CLTU_START_SEQUENCE >> 8));
    if (errors > 1u) {
        return false;
    }

    errors += __builtin_popcount(candidate[1] ^ (CLTU_START_SEQUENCE & 0xffu));
    return errors <= 1u;
}

/**
 * Prepare a streaming CLTU receiver.
 *
 * CLTU start and tail sequences are standard constants selected by this module
 * and Kconfig. When ccsds_cltu_rx_push() later acquires and decodes a complete
 * CLTU, @p on_frame is called with the decoded TC frame and @p user_data.
 */
int ccsds_cltu_rx_init(struct ccsds_cltu_rx *rx,
                       ccsds_cltu_frame_cb_t on_frame,
                       void *user_data);

/**
 * Drop any partially acquired CLTU while keeping receiver configuration.
 *
 * This preserves the configured markers, callback, and user_data. Use it after
 * loss of synchronization, buffer overflow, or when the caller wants the next
 * pushed byte to start a fresh acquisition attempt.
 */
void ccsds_cltu_rx_reset(struct ccsds_cltu_rx *rx);

/**
 * Feed bytes into a streaming CLTU receiver.
 *
 * Intended behavior: accept arbitrary byte chunks from a radio/transport,
 * search for the fixed start sequence, buffer bytes until the configured
 * standard tail sequence, decode the CLTU payload, and invoke the registered
 * callback.
 *
 * Currently returns -ENOTSUP.
 */
int ccsds_cltu_rx_push(struct ccsds_cltu_rx *rx, const uint8_t *chunk,
                       size_t chunk_len);

/**
 * Decode one complete CLTU buffer into a TC frame.
 *
 * This is the non-streaming primitive below ccsds_cltu_rx_push(): the caller
 * provides a complete CLTU that has already been bounded as one unit. The CLTU
 * must start with the fixed two-byte start sequence, followed by whole 8-byte
 * BCH(63,56) blocks. Each corrected block contributes its first 7 bytes to
 * @p tc_frame.
 *
 * @p tc_frame_len is the decoded CLTU payload length, not necessarily the TC
 * transfer-frame length from the TC header. Codeblock fill bytes may remain at
 * the end of @p tc_frame; TC frame parsing is responsible for applying the
 * applicable transfer-frame length rules and ignoring any trailing fill.
 */
int ccsds_cltu_decode_message(const uint8_t *cltu, size_t cltu_len,
                              uint8_t *tc_frame, size_t tc_frame_cap,
                              size_t *tc_frame_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CLTU_H */
