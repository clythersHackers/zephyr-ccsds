/**
 * @file ccsds_tc_segment.h
 * @brief CCSDS TC segment-header receive helpers.
 */

#ifndef AKIRA_CCSDS_TC_SEGMENT_H
#define AKIRA_CCSDS_TC_SEGMENT_H

#include "ccsds_tc_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CCSDS_TC_SEGMENT_HDR_LEN 1u
#define CCSDS_TC_MAP_ID_MAX 0x3fu

enum ccsds_tc_segment_boundary {
    CCSDS_TC_SEGMENT_CONTINUATION = 0,
    CCSDS_TC_SEGMENT_FIRST = 1,
    CCSDS_TC_SEGMENT_LAST = 2,
    CCSDS_TC_SEGMENT_UNSEGMENTED = 3,
};

struct ccsds_tc_segment {
    enum ccsds_tc_segment_boundary boundary;
    uint8_t map_id;
    const uint8_t *data;
    size_t data_len;
};

struct ccsds_tc_segment_part {
    uint8_t map_id;
    enum ccsds_tc_segment_boundary segment_boundary;
    bool starts_packet;
    bool ends_packet;
    const uint8_t *data;
    size_t data_len;
    size_t packet_len;
};

typedef int (*ccsds_tc_segment_part_handler_t)(
    const struct ccsds_tc_segment_part *part, void *user_data);

/**
 * @brief Decode a TC segment header and expose its data field.
 *
 * @param buf Segment bytes beginning with the one-byte segment header.
 * @param len Segment length in bytes.
 * @param segment Output decoded segment view.
 *
 * @return 0 on success, or -EINVAL for an empty segment.
 */
int ccsds_tc_segment_decode(const uint8_t *buf, size_t len,
                            struct ccsds_tc_segment *segment);

/**
 * @brief Decode the segment carried by a decoded TC frame.
 *
 * @param frame Decoded TC frame containing one TC segment.
 * @param segment Output decoded segment view.
 *
 * @return 0 on success, or -EINVAL for an empty frame data field.
 */
int ccsds_tc_segment_decode_frame(const struct ccsds_tc_frame *frame,
                                  struct ccsds_tc_segment *segment);

/**
 * @brief Walk packet-bearing parts visible in one TC segment.
 *
 * Complete Space Packets are reported as parts with both @c starts_packet and
 * @c ends_packet set. Split packet fragments are reported with only the
 * boundary bit that is known from the segment header and local packet length
 * field, if present.
 *
 * @param segment Decoded TC segment.
 * @param handler Callback invoked for each visible packet or packet fragment.
 * @param user_data Opaque pointer passed to @p handler.
 *
 * @return 0 on success, the first handler error, or -EINVAL for invalid segment
 *         boundary/data consistency.
 */
int ccsds_tc_segment_walk_parts(
    const struct ccsds_tc_segment *segment,
    ccsds_tc_segment_part_handler_t handler, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_TC_SEGMENT_H */
