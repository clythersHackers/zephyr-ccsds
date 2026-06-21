/**
 * @file ccsds_bch.h
 * @brief CCSDS BCH(63,56) primitive boundary.
 */

#ifndef AKIRA_CCSDS_BCH_H
#define AKIRA_CCSDS_BCH_H

#include "ccsds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum ccsds_bch_result {
    CCSDS_BCH_OK = 0,
    CCSDS_BCH_CORRECTED = 1,
    CCSDS_BCH_DETECTED_EVEN = 2,
    CCSDS_BCH_DETECTED_ODD = 3,
};

#define CCSDS_BCH_BLOCK_SIZE 8u
#define CCSDS_BCH_DATA_SIZE 7u

/**
 * Decode one CCSDS BCH(63,56) codeblock.
 *
 * @param block One 8-byte block: 56 data bits, 7 inverted BCH parity bits,
 *              and one filler bit. The filler bit is not checked or corrected.
 * @param data Output buffer for the corrected 56 data bits.
 * @param corrected_bit Optional output set to the corrected bit index 0..62,
 *                      or -1 when no single-bit correction was applied.
 *
 * This primitive intentionally handles a single BCH block only. CLTU start,
 * tail, and multi-block framing are handled by higher CCSDS layers.
 */
int ccsds_bch_decode_block(const uint8_t block[CCSDS_BCH_BLOCK_SIZE],
                           uint8_t data[CCSDS_BCH_DATA_SIZE],
                           int *corrected_bit);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_BCH_H */
