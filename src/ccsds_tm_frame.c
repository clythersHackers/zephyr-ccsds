#include "ccsds_tm_frame.h"

#include <errno.h>
#include <zephyr/sys/util.h>

int ccsds_tm_frame_encode(const struct ccsds_tm_frame *frame,
                          uint8_t *buf, size_t cap, size_t *len)
{
    ARG_UNUSED(frame);
    ARG_UNUSED(buf);
    ARG_UNUSED(cap);
    ARG_UNUSED(len);

    return -ENOTSUP;
}
