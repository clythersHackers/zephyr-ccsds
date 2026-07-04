#include "ccsds_tc_segment.h"

#include <errno.h>
#include <string.h>

#include <zephyr/sys/__assert.h>
#include <zephyr/sys/byteorder.h>

#define CCSDS_TC_SEGMENT_BOUNDARY_MASK 0x03u
#define CCSDS_TC_SEGMENT_MAP_MASK 0x3fu
#define CCSDS_TC_SEGMENT_BOUNDARY(header) \
    (((header) >> 6) & CCSDS_TC_SEGMENT_BOUNDARY_MASK)
#define CCSDS_TC_SEGMENT_MAP_ID(header) ((header) & CCSDS_TC_SEGMENT_MAP_MASK)

static bool segment_ends_packet(enum ccsds_tc_segment_boundary boundary)
{
    return boundary == CCSDS_TC_SEGMENT_LAST ||
           boundary == CCSDS_TC_SEGMENT_UNSEGMENTED;
}

static size_t encoded_packet_len(const uint8_t *packet)
{
    uint16_t length_field = sys_get_be16(&packet[4]);

    return CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + (size_t)length_field + 1u;
}

static int emit_part(const struct ccsds_tc_segment *segment,
                     bool starts_packet, bool ends_packet, const uint8_t *data,
                     size_t data_len, size_t packet_len,
                     ccsds_tc_segment_part_handler_t handler, void *user_data)
{
    struct ccsds_tc_segment_part part = {
        .map_id = segment->map_id,
        .segment_boundary = segment->boundary,
        .starts_packet = starts_packet,
        .ends_packet = ends_packet,
        .data = data,
        .data_len = data_len,
        .packet_len = packet_len,
    };

    return handler(&part, user_data);
}

int ccsds_tc_segment_decode(const uint8_t *buf, size_t len,
                            struct ccsds_tc_segment *segment)
{
    __ASSERT(buf != NULL, "TC segment input buffer is NULL");
    __ASSERT(segment != NULL, "TC segment output is NULL");

    memset(segment, 0, sizeof(*segment));

    if (len < CCSDS_TC_SEGMENT_HDR_LEN) {
        return -EINVAL;
    }

    segment->boundary =
        (enum ccsds_tc_segment_boundary)CCSDS_TC_SEGMENT_BOUNDARY(buf[0]);
    segment->map_id = CCSDS_TC_SEGMENT_MAP_ID(buf[0]);
    segment->data = &buf[CCSDS_TC_SEGMENT_HDR_LEN];
    segment->data_len = len - CCSDS_TC_SEGMENT_HDR_LEN;

    return 0;
}

int ccsds_tc_segment_decode_frame(const struct ccsds_tc_frame *frame,
                                  struct ccsds_tc_segment *segment)
{
    __ASSERT(frame != NULL, "TC frame is NULL");
    __ASSERT(segment != NULL, "TC segment output is NULL");

    return ccsds_tc_segment_decode(frame->data, frame->data_len, segment);
}

int ccsds_tc_segment_walk_parts(
    const struct ccsds_tc_segment *segment,
    ccsds_tc_segment_part_handler_t handler, void *user_data)
{
    size_t offset = 0u;
    int ret;

    __ASSERT(segment != NULL, "TC segment is NULL");
    __ASSERT(handler != NULL, "TC segment handler is NULL");

    if (segment->data_len == 0u) {
        return -EINVAL;
    }

    if (segment->boundary == CCSDS_TC_SEGMENT_CONTINUATION ||
        segment->boundary == CCSDS_TC_SEGMENT_LAST) {
        return emit_part(segment, false, segment_ends_packet(segment->boundary),
                         segment->data, segment->data_len, 0u, handler,
                         user_data);
    }

    if (segment->boundary == CCSDS_TC_SEGMENT_FIRST) {
        size_t packet_len;

        if (segment->data_len < CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN) {
            return -EINVAL;
        }

        packet_len = encoded_packet_len(segment->data);
        if (packet_len <= segment->data_len) {
            return -EINVAL;
        }

        return emit_part(segment, true, false, segment->data,
                         segment->data_len, packet_len, handler, user_data);
    }

    while (offset < segment->data_len) {
        const uint8_t *data = &segment->data[offset];
        size_t remaining = segment->data_len - offset;
        size_t packet_len;

        if (remaining < CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN) {
            return -EINVAL;
        }

        packet_len = encoded_packet_len(data);
        if (packet_len > remaining) {
            return -EINVAL;
        }

        ret = emit_part(segment, true, true, data, packet_len, packet_len,
                        handler, user_data);
        if (ret != 0) {
            return ret;
        }

        offset += packet_len;
    }

    return 0;
}
