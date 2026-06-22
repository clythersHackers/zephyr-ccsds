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

struct ccsds_rs_config {
    uint8_t interleave_depth;
    bool dual_basis;
};

#define CCSDS_RS_DATA_LEN 223u
#define CCSDS_RS_PARITY_LEN 32u
#define CCSDS_RS_CODEBLOCK_LEN (CCSDS_RS_DATA_LEN + CCSDS_RS_PARITY_LEN)

int ccsds_rs_encode(const struct ccsds_rs_config *cfg,
                    const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_RS_H */
