#include "ccsds_bch.h"

#include <errno.h>
#include <zephyr/sys/util.h>

int ccsds_bch_decode_block(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len,
                           unsigned int *corrected_bits)
{
    ARG_UNUSED(in);
    ARG_UNUSED(in_len);
    ARG_UNUSED(out);
    ARG_UNUSED(out_cap);
    ARG_UNUSED(out_len);
    ARG_UNUSED(corrected_bits);

    return -ENOTSUP;
}
