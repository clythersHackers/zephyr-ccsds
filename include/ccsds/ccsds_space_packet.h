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

/**
 * @brief Return the encoded Space Packet length for a payload size.
 *
 * @param payload_len Payload length in bytes.
 *
 * @return Primary-header length plus @p payload_len.
 */
size_t ccsds_space_packet_encoded_len(size_t payload_len);

/**
 * @brief Decode a CCSDS Space Packet primary header and payload view.
 *
 * @param buf Encoded Space Packet bytes.
 * @param len Length of @p buf in bytes.
 * @param packet Output decoded packet view. The payload points into @p buf.
 *
 * @return 0 on success, -EINVAL for invalid input, or -EMSGSIZE if @p len is
 *         shorter than the packet length field.
 */
int ccsds_space_packet_decode(const uint8_t *buf, size_t len,
                              struct ccsds_space_packet *packet);

/**
 * @brief Encode a CCSDS Space Packet primary header and payload.
 *
 * @param packet Packet fields and payload to encode.
 * @param buf Output buffer for encoded bytes.
 * @param cap Output buffer capacity in bytes.
 * @param len Written encoded packet length.
 *
 * @return 0 on success, -EINVAL for invalid packet fields or pointers, or
 *         -ENOSPC when @p cap is too small.
 */
int ccsds_space_packet_encode(const struct ccsds_space_packet *packet,
                              uint8_t *buf, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_SPACE_PACKET_H */
