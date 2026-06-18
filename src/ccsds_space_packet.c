#include "ccsds_space_packet.h"

#include <errno.h>
#include <string.h>

size_t ccsds_space_packet_encoded_len(size_t payload_len)
{
    return CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + payload_len;
}

int ccsds_space_packet_decode(const uint8_t *buf, size_t len,
                              struct ccsds_space_packet *packet)
{
    if (!buf || !packet || len < CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN) {
        return -EINVAL;
    }

    uint16_t word0 = ((uint16_t)buf[0] << 8) | buf[1];
    uint16_t word1 = ((uint16_t)buf[2] << 8) | buf[3];
    uint16_t length_field = ((uint16_t)buf[4] << 8) | buf[5];
    size_t payload_len = (size_t)length_field + 1u;

    if (len < CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + payload_len) {
        return -EMSGSIZE;
    }

    packet->version = (uint8_t)((word0 >> 13) & 0x7u);
    packet->type = (enum ccsds_packet_type)((word0 >> 12) & 0x1u);
    packet->secondary_header = ((word0 & 0x0800u) != 0u);
    packet->apid = word0 & CCSDS_APID_MAX;
    packet->sequence_flags = (enum ccsds_sequence_flags)((word1 >> 14) & 0x3u);
    packet->sequence_count = word1 & 0x3fffu;
    packet->payload = &buf[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN];
    packet->payload_len = payload_len;

    return 0;
}

int ccsds_space_packet_encode(const struct ccsds_space_packet *packet,
                              uint8_t *buf, size_t cap, size_t *len)
{
    if (!packet || !buf || !len || packet->apid > CCSDS_APID_MAX ||
        packet->sequence_count > 0x3fffu || packet->payload_len == 0u ||
        packet->payload_len > 0x10000u || !packet->payload) {
        return -EINVAL;
    }

    size_t needed = ccsds_space_packet_encoded_len(packet->payload_len);
    if (cap < needed) {
        return -ENOSPC;
    }

    uint16_t word0 = ((uint16_t)(packet->version & 0x7u) << 13) |
                     ((uint16_t)(packet->type & 0x1u) << 12) |
                     (packet->secondary_header ? 0x0800u : 0u) |
                     (packet->apid & CCSDS_APID_MAX);
    uint16_t word1 = ((uint16_t)(packet->sequence_flags & 0x3u) << 14) |
                     (packet->sequence_count & 0x3fffu);
    uint16_t length_field = (uint16_t)(packet->payload_len - 1u);

    buf[0] = (uint8_t)(word0 >> 8);
    buf[1] = (uint8_t)word0;
    buf[2] = (uint8_t)(word1 >> 8);
    buf[3] = (uint8_t)word1;
    buf[4] = (uint8_t)(length_field >> 8);
    buf[5] = (uint8_t)length_field;

    memcpy(&buf[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN], packet->payload,
           packet->payload_len);

    *len = needed;
    return 0;
}
