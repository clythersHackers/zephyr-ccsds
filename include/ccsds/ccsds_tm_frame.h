/**
 * @file ccsds_tm_frame.h
 * @brief CCSDS TM transfer frame boundary.
 */

#ifndef AKIRA_CCSDS_TM_FRAME_H
#define AKIRA_CCSDS_TM_FRAME_H

#include "ccsds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_tm_frame {
    uint16_t spacecraft_id;
    uint8_t virtual_channel_id;
    uint8_t master_channel_frame_count;
    uint8_t virtual_channel_frame_count;
    const uint8_t *data;
    size_t data_len;
};

int ccsds_tm_frame_encode(const struct ccsds_tm_frame *frame,
                          uint8_t *buf, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_TM_FRAME_H */
