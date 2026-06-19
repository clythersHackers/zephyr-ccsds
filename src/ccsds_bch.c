#include "ccsds_bch.h"

#include <errno.h>

/* Single BCH(63,56) block decoder; CLTU framing stays above this layer. */
int ccsds_bch_decode_block(uint8_t block[CCSDS_BCH_BLOCK_SIZE],
                           int *corrected_bit)
{
    uint8_t syndrome = 0u;
    bool odd_parity = false;

    if (!block) {
        return -EINVAL;
    }

    if (corrected_bit) {
        *corrected_bit = -1;
    }

    for (int i = 0; i < 63; i++) {
        uint8_t bit = (block[i / 8] >> (7 - (i % 8))) & 1u;
        const bool carry = (syndrome & 0x20u) != 0u;

        if (i >= 56) {
            bit ^= 1u;
        }

        odd_parity ^= bit != 0u;
        syndrome = ((syndrome << 1) & 0x3fu) | bit;
        if (carry) {
            syndrome ^= 0x03u;
        }
    }

    if (syndrome == 0u) {
        return odd_parity ? CCSDS_BCH_DETECTED_ODD : CCSDS_BCH_OK;
    }

    if (!odd_parity) {
        return CCSDS_BCH_DETECTED_EVEN;
    }

    for (int i = 0, single = 0x21; i < 63; i++) {
        if (syndrome == single) {
            block[i / 8] ^= (uint8_t)(0x80u >> (i % 8));
            if (corrected_bit) {
                *corrected_bit = i;
            }
            return CCSDS_BCH_CORRECTED;
        }

        single = (single & 1) ? (((single ^ 0x03) >> 1) | 0x20) :
                                (single >> 1);
    }

    return CCSDS_BCH_DETECTED_ODD;
}
