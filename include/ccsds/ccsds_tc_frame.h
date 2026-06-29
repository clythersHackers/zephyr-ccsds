/**
 * @file ccsds_tc_frame.h
 * @brief CCSDS TC transfer frame boundary.
 */

#ifndef AKIRA_CCSDS_TC_FRAME_H
#define AKIRA_CCSDS_TC_FRAME_H

#include "ccsds_space_packet.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_tc_frame {
    uint16_t spacecraft_id;
    uint8_t virtual_channel_id;
    bool bypass;
    bool control_command;
    uint8_t frame_sequence_number;
    const uint8_t *data;
    size_t data_len;
};

/**
 * @brief Decode a CCSDS TC transfer frame.
 *
 * @param buf Encoded TC transfer frame bytes, optionally followed by decoded
 *        CLTU fill bytes.
 * @param len Length of @p buf in bytes. This may be larger than the transfer
 *        frame length field when CLTU fill bytes are present.
 * @param frame Output decoded frame view.
 *
 * @return 0 on success, -EINVAL for invalid arguments or malformed fields,
 *         -EMSGSIZE for invalid length or fill, or -EACCES for a wrong
 *         spacecraft ID.
 */
int ccsds_tc_frame_decode(const uint8_t *buf, size_t len,
                          struct ccsds_tc_frame *frame);

/**
 * @brief Decode the Space Packet carried by a decoded TC frame.
 *
 * @param frame Decoded TC frame containing packet data.
 * @param packet Output decoded Space Packet view. The payload points into
 *        @p frame data.
 *
 * @return 0 on success, -EINVAL for invalid input, or a Space Packet decode
 *         error.
 */
int ccsds_tc_frame_extract_packet(const struct ccsds_tc_frame *frame,
                                  struct ccsds_space_packet *packet);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_TC_FRAME_H */
