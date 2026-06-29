#include "ccsds_tc_frame.h"

#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#define CCSDS_TC_PRIMARY_HDR_LEN 5u
#define CCSDS_TC_FILL_BYTE 0x55u
#define CCSDS_TC_VERSION_MASK 0x03u
#define CCSDS_TC_RESERVED_MASK 0x03u
#define CCSDS_TC_MAX_SCID 0x03ffu
#define CCSDS_TC_MAX_FRAME_LEN_FIELD 0x03ffu
#define CCSDS_TC_VERSION(byte0) (((byte0) >> 6) & CCSDS_TC_VERSION_MASK)
#define CCSDS_TC_BYPASS(byte0) (((byte0) & BIT(5)) != 0u)
#define CCSDS_TC_CONTROL(byte0) (((byte0) & BIT(4)) != 0u)
#define CCSDS_TC_RESERVED(byte0) (((byte0) >> 2) & CCSDS_TC_RESERVED_MASK)

LOG_MODULE_REGISTER(ccsds_tc_frame, CONFIG_AKIRA_LOG_LEVEL);

BUILD_ASSERT(CONFIG_AKIRA_CCSDS_SPACECRAFT_ID <= CCSDS_TC_MAX_SCID,
             "CCSDS spacecraft ID must fit in 10 bits");

int ccsds_tc_frame_decode(const uint8_t *buf, size_t len,
                          struct ccsds_tc_frame *frame)
{
    if (!buf || !frame) {
        LOG_WRN("TC frame decode called with null argument");
        return -EINVAL;
    }

    memset(frame, 0, sizeof(*frame));

    if (len < CCSDS_TC_PRIMARY_HDR_LEN) {
        LOG_WRN("TC frame too short: %zu bytes", len);
        return -EINVAL;
    }

    uint8_t version = CCSDS_TC_VERSION(buf[0]);
    if (version != 0u) {
        LOG_WRN("TC frame unsupported version: %u", version);
        return -EINVAL;
    }

    uint16_t frame_len_field = (uint16_t)((((uint16_t)buf[2] & 0x03u) << 8) |
                                          buf[3]);
    size_t frame_len = (size_t)frame_len_field + 1u;
    if (frame_len < CCSDS_TC_PRIMARY_HDR_LEN) {
        LOG_WRN("TC frame length field too small: %zu bytes", frame_len);
        return -EMSGSIZE;
    }

    if (frame_len > len) {
        LOG_WRN("TC frame length exceeds input: field=%zu actual=%zu",
                frame_len, len);
        return -EMSGSIZE;
    }

    if (frame_len < len &&
        (buf[frame_len] != CCSDS_TC_FILL_BYTE ||
         buf[len - 1u] != CCSDS_TC_FILL_BYTE)) {
        LOG_WRN("TC frame invalid fill: first=0x%02x last=0x%02x",
                buf[frame_len], buf[len - 1u]);
        return -EMSGSIZE;
    }

    uint16_t spacecraft_id = (uint16_t)((((uint16_t)buf[0] & 0x03u) << 8) |
                                        buf[1]);
    if (spacecraft_id != CONFIG_AKIRA_CCSDS_SPACECRAFT_ID) {
        LOG_WRN("TC frame wrong spacecraft id: scid=%u expected=%u",
                spacecraft_id, CONFIG_AKIRA_CCSDS_SPACECRAFT_ID);
        return -EACCES;
    }

    frame->spacecraft_id = spacecraft_id;
    frame->virtual_channel_id = (uint8_t)((buf[2] >> 2) & 0x3fu);
    frame->bypass = CCSDS_TC_BYPASS(buf[0]);
    frame->control_command = CCSDS_TC_CONTROL(buf[0]);
    frame->frame_sequence_number = buf[4];
    frame->data = &buf[CCSDS_TC_PRIMARY_HDR_LEN];
    frame->data_len = frame_len - CCSDS_TC_PRIMARY_HDR_LEN;

    return 0;
}

int ccsds_tc_frame_extract_packet(const struct ccsds_tc_frame *frame,
                                  struct ccsds_space_packet *packet)
{
    if (!frame || !packet) {
        return -EINVAL;
    }

    return ccsds_space_packet_decode(frame->data, frame->data_len, packet);
}
