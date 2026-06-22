/**
 * @file ccsds_tm_frame.h
 * @brief CCSDS TM transfer frame packet admission boundary.
 */

#ifndef AKIRA_CCSDS_TM_FRAME_H
#define AKIRA_CCSDS_TM_FRAME_H

#include "ccsds_types.h"

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

int ccsds_tm_frame_init(void);

int ccsds_tm_frame_add(uint8_t vcid, const uint8_t *packet, size_t packet_len,
                       k_timeout_t timeout);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_TM_FRAME_H */
