/**
 * @file ccsds_tc_frame.h
 * @brief CCSDS TC transfer frame boundary.
 */

#ifndef AKIRA_CCSDS_TC_FRAME_H
#define AKIRA_CCSDS_TC_FRAME_H

#include "ccsds_space_packet.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_tc_frame {
    uint16_t spacecraft_id;
    uint8_t virtual_channel_id;
    bool bypass;
    bool control_command;
    uint8_t frame_sequence_number;
    const uint8_t *data;
    size_t data_len;
};

int ccsds_tc_frame_decode(const uint8_t *buf, size_t len,
                          struct ccsds_tc_frame *frame);

int ccsds_tc_frame_extract_packet(const struct ccsds_tc_frame *frame,
                                  struct ccsds_space_packet *packet);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_TC_FRAME_H */
