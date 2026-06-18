#include "ccsds_cltu.h"

#include <errno.h>
#include <string.h>
#include <zephyr/sys/util.h>

int ccsds_cltu_rx_init(struct ccsds_cltu_rx *rx,
                       const struct ccsds_cltu_rx_config *cfg,
                       ccsds_cltu_frame_cb_t on_frame,
                       void *user_data)
{
    if (!rx || !cfg || !cfg->start_sequence || cfg->start_sequence_len == 0u ||
        !cfg->tail_sequence || cfg->tail_sequence_len == 0u || !on_frame) {
        return -EINVAL;
    }

    memset(rx, 0, sizeof(*rx));
    rx->cfg = *cfg;
    rx->on_frame = on_frame;
    rx->user_data = user_data;
    return 0;
}

void ccsds_cltu_rx_reset(struct ccsds_cltu_rx *rx)
{
    if (!rx) {
        return;
    }

    rx->buffered_len = 0u;
    rx->in_cltu = false;
}

int ccsds_cltu_rx_push(struct ccsds_cltu_rx *rx, const uint8_t *chunk,
                       size_t chunk_len)
{
    ARG_UNUSED(rx);
    ARG_UNUSED(chunk);
    ARG_UNUSED(chunk_len);

    return -ENOTSUP;
}

int ccsds_cltu_decode_message(const uint8_t *cltu, size_t cltu_len,
                              uint8_t *tc_frame, size_t tc_frame_cap,
                              size_t *tc_frame_len)
{
    ARG_UNUSED(cltu);
    ARG_UNUSED(cltu_len);
    ARG_UNUSED(tc_frame);
    ARG_UNUSED(tc_frame_cap);
    ARG_UNUSED(tc_frame_len);

    return -ENOTSUP;
}
