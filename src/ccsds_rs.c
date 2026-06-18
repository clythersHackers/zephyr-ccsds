#include "ccsds_rs.h"

#include <errno.h>
#include <zephyr/sys/util.h>

int ccsds_rs_encode(const struct ccsds_rs_config *cfg,
                    const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    ARG_UNUSED(cfg);
    ARG_UNUSED(data);
    ARG_UNUSED(data_len);
    ARG_UNUSED(out);
    ARG_UNUSED(out_cap);
    ARG_UNUSED(out_len);

    return -ENOTSUP;
}
