/**
 * @file ccsds_rs.h
 * @brief Reed-Solomon primitive boundary for CCSDS frame coding.
 */

#ifndef AKIRA_CCSDS_RS_H
#define AKIRA_CCSDS_RS_H

#include "ccsds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_AKIRA_CCSDS_RS_INTERLEAVE_DEPTH
#define CONFIG_AKIRA_CCSDS_RS_INTERLEAVE_DEPTH 5
#endif

#define CCSDS_RS_DATA_LEN 223u
#define CCSDS_RS_PARITY_LEN 32u
#define CCSDS_RS_CODEBLOCK_LEN (CCSDS_RS_DATA_LEN + CCSDS_RS_PARITY_LEN)
#define CCSDS_RS_INTERLEAVE_DEPTH CONFIG_AKIRA_CCSDS_RS_INTERLEAVE_DEPTH
#define CCSDS_RS_INTERLEAVED_DATA_LEN \
    (CCSDS_RS_DATA_LEN * CCSDS_RS_INTERLEAVE_DEPTH)
#define CCSDS_RS_INTERLEAVED_PARITY_LEN \
    (CCSDS_RS_PARITY_LEN * CCSDS_RS_INTERLEAVE_DEPTH)

void ccsds_rs_encode(const uint8_t data[CCSDS_RS_INTERLEAVED_DATA_LEN],
                     uint8_t parity[CCSDS_RS_INTERLEAVED_PARITY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_RS_H */
