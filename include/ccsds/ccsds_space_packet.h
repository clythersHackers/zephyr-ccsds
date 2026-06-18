/**
 * @file ccsds_space_packet.h
 * @brief CCSDS Space Packet encode/decode boundary.
 */

#ifndef AKIRA_CCSDS_SPACE_PACKET_H
#define AKIRA_CCSDS_SPACE_PACKET_H

#include "ccsds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_space_packet {
    uint8_t version;
    enum ccsds_packet_type type;
    bool secondary_header;
    uint16_t apid;
    enum ccsds_sequence_flags sequence_flags;
    uint16_t sequence_count;
    const uint8_t *payload;
    size_t payload_len;
};

size_t ccsds_space_packet_encoded_len(size_t payload_len);

int ccsds_space_packet_decode(const uint8_t *buf, size_t len,
                              struct ccsds_space_packet *packet);

int ccsds_space_packet_encode(const struct ccsds_space_packet *packet,
                              uint8_t *buf, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_SPACE_PACKET_H */
