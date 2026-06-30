/**
 * @file ccsds_rnd.h
 * @brief Optional CCSDS randomization primitive.
 */

#ifndef AKIRA_CCSDS_RND_H
#define AKIRA_CCSDS_RND_H

#include "ccsds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Randomize or derandomize a CCSDS byte stream in place.
 *
 * CCSDS randomization is self-inverse: applying the same pseudo-random
 * sequence a second time restores the original bytes.
 *
 * @param data Byte stream to randomize or derandomize.
 * @param len Number of bytes in @p data.
 */
void ccsds_rnd_apply(uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_RND_H */
