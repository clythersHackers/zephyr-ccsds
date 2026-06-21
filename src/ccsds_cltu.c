#include "ccsds_cltu.h"

#include <errno.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(ccsds_cltu, CONFIG_AKIRA_LOG_LEVEL);

int ccsds_cltu_rx_init(struct ccsds_cltu_rx *rx,
                       ccsds_cltu_frame_cb_t on_frame,
                       void *user_data)
{
    if (!rx || !on_frame) {
        return -EINVAL;
    }

    memset(rx, 0, sizeof(*rx));
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
    const size_t start_len = sizeof(uint16_t);
    const size_t min_len = start_len + CCSDS_BCH_BLOCK_SIZE;
    size_t bch_len;
    size_t block_count;
    size_t decoded_len;

    if (!cltu || !tc_frame || !tc_frame_len) {
        LOG_WRN("CLTU decode called with null argument");
        return -EINVAL;
    }

    *tc_frame_len = 0u;

    if (cltu_len < min_len) {
        LOG_WRN("CLTU too short: %zu bytes", cltu_len);
        return -EINVAL;
    }

    if (cltu_len > CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN) {
        LOG_WRN("CLTU too long: %zu bytes", cltu_len);
        return -EINVAL;
    }

    if (!ccsds_cltu_is_start_sequence(cltu)) {
        LOG_WRN("CLTU start sequence not found");
        return -EINVAL;
    }

    bch_len = cltu_len - start_len;
    if ((bch_len % CCSDS_BCH_BLOCK_SIZE) != 0u) {
        LOG_WRN("CLTU BCH body length is not block-aligned: %zu bytes",
                bch_len);
        return -EINVAL;
    }

    block_count = bch_len / CCSDS_BCH_BLOCK_SIZE;
    decoded_len = block_count * CCSDS_BCH_DATA_SIZE;
    if (tc_frame_cap < decoded_len) {
        LOG_WRN("TC frame buffer too small: need %zu bytes, have %zu",
                decoded_len, tc_frame_cap);
        return -ENOSPC;
    }

    for (size_t block_index = 0u; block_index < block_count; block_index++) {
        const size_t in_offset = start_len +
                                 (block_index * CCSDS_BCH_BLOCK_SIZE);
        const size_t out_offset = block_index * CCSDS_BCH_DATA_SIZE;
        int corrected_bit = -1;
        int ret;

        ret = ccsds_bch_decode_block(cltu + in_offset,
                                     tc_frame + out_offset,
                                     &corrected_bit);
        switch (ret) {
        case CCSDS_BCH_OK:
            break;
        case CCSDS_BCH_CORRECTED:
            LOG_WRN("CLTU BCH corrected block %zu bit %d",
                    block_index, corrected_bit);
            break;
        case CCSDS_BCH_DETECTED_EVEN:
            LOG_WRN("CLTU BCH detected even-numbered errors in block %zu",
                    block_index);
            return -EIO;
        case CCSDS_BCH_DETECTED_ODD:
            LOG_WRN("CLTU BCH detected odd-numbered errors in block %zu",
                    block_index);
            return -EIO;
        default:
            LOG_ERR("CLTU BCH decoder returned unexpected result %d", ret);
            return -EIO;
        }
    }

    *tc_frame_len = decoded_len;
    return 0;
}
