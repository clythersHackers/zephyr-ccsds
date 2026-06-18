/**
 * @file ccsds_bch.h
 * @brief BCH primitive boundary for CCSDS CLTU handling.
 */

#ifndef AKIRA_CCSDS_BCH_H
#define AKIRA_CCSDS_BCH_H

#include "ccsds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int ccsds_bch_decode_block(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len,
                           unsigned int *corrected_bits);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_BCH_H */
