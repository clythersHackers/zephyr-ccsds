#include "ccsds_tc_frame.h"

#include <errno.h>
#include <zephyr/sys/util.h>

int ccsds_tc_frame_decode(const uint8_t *buf, size_t len,
                          struct ccsds_tc_frame *frame)
{
    ARG_UNUSED(buf);
    ARG_UNUSED(len);
    ARG_UNUSED(frame);

    return -ENOTSUP;
}

int ccsds_tc_frame_extract_packet(const struct ccsds_tc_frame *frame,
                                  struct ccsds_space_packet *packet)
{
    if (!frame || !packet) {
        return -EINVAL;
    }

    return ccsds_space_packet_decode(frame->data, frame->data_len, packet);
}
