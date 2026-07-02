#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ccsds/ccsds_tc_segment.h"

#define TEST_SEG_HDR(boundary, map_id) \
    (uint8_t)((((uint8_t)(boundary) & 0x03u) << 6) | ((map_id) & 0x3fu))
#define TEST_PACKET_HDR_LEN CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN

struct part_capture {
    struct ccsds_tc_segment_part parts[4];
    size_t count;
};

static void build_packet(uint8_t *buf, size_t payload_len, size_t available_len,
                         uint16_t apid, uint8_t seed)
{
    size_t packet_len = TEST_PACKET_HDR_LEN + payload_len;
    uint16_t length_field = (uint16_t)(payload_len - 1u);

    zassert_true(available_len >= TEST_PACKET_HDR_LEN);
    zassert_true(available_len <= packet_len);

    memset(buf, 0, available_len);
    buf[0] = (uint8_t)(0x10u | ((apid >> 8) & 0x07u));
    buf[1] = (uint8_t)apid;
    buf[2] = (uint8_t)(CCSDS_SEQUENCE_UNSEGMENTED << 6);
    buf[4] = (uint8_t)(length_field >> 8);
    buf[5] = (uint8_t)length_field;

    for (size_t i = 0u; i < available_len - TEST_PACKET_HDR_LEN; i++) {
        buf[TEST_PACKET_HDR_LEN + i] = seed + (uint8_t)i;
    }
}

static int capture_part(const struct ccsds_tc_segment_part *part,
                        void *user_data)
{
    struct part_capture *capture = user_data;

    zassert_true(capture->count < ARRAY_SIZE(capture->parts));
    capture->parts[capture->count++] = *part;

    return 0;
}

ZTEST(ccsds_tc_segment, test_decode_extracts_boundary_and_map_id)
{
    uint8_t bytes[] = {
        TEST_SEG_HDR(CCSDS_TC_SEGMENT_LAST, 42u),
        0xaau,
        0xbbu,
    };
    struct ccsds_tc_segment segment;

    zassert_ok(ccsds_tc_segment_decode(bytes, sizeof(bytes), &segment));
    zassert_equal(segment.boundary, CCSDS_TC_SEGMENT_LAST);
    zassert_equal(segment.map_id, 42u);
    zassert_equal(segment.data, &bytes[CCSDS_TC_SEGMENT_HDR_LEN]);
    zassert_equal(segment.data_len, 2u);
}

ZTEST(ccsds_tc_segment, test_walk_reports_aggregated_complete_packets)
{
    uint8_t bytes[1u + 8u + 9u];
    struct ccsds_tc_segment segment;
    struct part_capture capture = {0};

    bytes[0] = TEST_SEG_HDR(CCSDS_TC_SEGMENT_UNSEGMENTED, 7u);
    build_packet(&bytes[1], 2u, 8u, 0x21u, 0x80u);
    build_packet(&bytes[9], 3u, 9u, 0x22u, 0x90u);

    zassert_ok(ccsds_tc_segment_decode(bytes, sizeof(bytes), &segment));
    zassert_ok(ccsds_tc_segment_walk_parts(&segment, capture_part,
                                           &capture));

    zassert_equal(capture.count, 2u);
    zassert_true(capture.parts[0].starts_packet);
    zassert_true(capture.parts[0].ends_packet);
    zassert_equal(capture.parts[0].map_id, 7u);
    zassert_equal(capture.parts[0].data_len, 8u);
    zassert_equal(capture.parts[0].packet_len, 8u);
    zassert_equal(capture.parts[1].data, &bytes[9]);
    zassert_equal(capture.parts[1].data_len, 9u);
}

ZTEST(ccsds_tc_segment, test_walk_reports_first_fragment)
{
    uint8_t bytes[1u + 8u];
    struct ccsds_tc_segment segment;
    struct part_capture capture = {0};

    bytes[0] = TEST_SEG_HDR(CCSDS_TC_SEGMENT_FIRST, 3u);
    build_packet(&bytes[1], 12u, 8u, 0x31u, 0xa0u);

    zassert_ok(ccsds_tc_segment_decode(bytes, sizeof(bytes), &segment));
    zassert_ok(ccsds_tc_segment_walk_parts(&segment, capture_part,
                                           &capture));

    zassert_equal(capture.count, 1u);
    zassert_true(capture.parts[0].starts_packet);
    zassert_false(capture.parts[0].ends_packet);
    zassert_equal(capture.parts[0].data, &bytes[1]);
    zassert_equal(capture.parts[0].data_len, 8u);
    zassert_equal(capture.parts[0].packet_len, 18u);
}

ZTEST(ccsds_tc_segment, test_walk_rejects_first_without_primary_header)
{
    uint8_t bytes[] = {
        TEST_SEG_HDR(CCSDS_TC_SEGMENT_FIRST, 3u),
        0x01u,
        0x02u,
        0x03u,
    };
    struct ccsds_tc_segment segment;
    struct part_capture capture = {0};

    zassert_ok(ccsds_tc_segment_decode(bytes, sizeof(bytes), &segment));
    zassert_equal(ccsds_tc_segment_walk_parts(&segment, capture_part,
                                              &capture),
                  -EINVAL);
    zassert_equal(capture.count, 0u);
}

ZTEST(ccsds_tc_segment, test_walk_rejects_complete_packet_in_first_segment)
{
    uint8_t bytes[1u + 8u];
    struct ccsds_tc_segment segment;
    struct part_capture capture = {0};

    bytes[0] = TEST_SEG_HDR(CCSDS_TC_SEGMENT_FIRST, 3u);
    build_packet(&bytes[1], 2u, 8u, 0x31u, 0xa0u);

    zassert_ok(ccsds_tc_segment_decode(bytes, sizeof(bytes), &segment));
    zassert_equal(ccsds_tc_segment_walk_parts(&segment, capture_part,
                                              &capture),
                  -EINVAL);
    zassert_equal(capture.count, 0u);
}

ZTEST(ccsds_tc_segment, test_walk_reports_continuation_fragment)
{
    uint8_t bytes[] = {
        TEST_SEG_HDR(CCSDS_TC_SEGMENT_CONTINUATION, 12u),
        0x01u,
        0x02u,
        0x03u,
    };
    struct ccsds_tc_segment segment;
    struct part_capture capture = {0};

    zassert_ok(ccsds_tc_segment_decode(bytes, sizeof(bytes), &segment));
    zassert_ok(ccsds_tc_segment_walk_parts(&segment, capture_part,
                                           &capture));

    zassert_equal(capture.count, 1u);
    zassert_false(capture.parts[0].starts_packet);
    zassert_false(capture.parts[0].ends_packet);
    zassert_equal(capture.parts[0].map_id, 12u);
    zassert_equal(capture.parts[0].data_len, 3u);
    zassert_equal(capture.parts[0].packet_len, 0u);
}

ZTEST(ccsds_tc_segment, test_walk_rejects_truncated_unsegmented_packet)
{
    uint8_t bytes[1u + 8u];
    struct ccsds_tc_segment segment;
    struct part_capture capture = {0};

    bytes[0] = TEST_SEG_HDR(CCSDS_TC_SEGMENT_UNSEGMENTED, 0u);
    build_packet(&bytes[1], 12u, 8u, 0x41u, 0xb0u);

    zassert_ok(ccsds_tc_segment_decode(bytes, sizeof(bytes), &segment));
    zassert_equal(ccsds_tc_segment_walk_parts(&segment, capture_part,
                                              &capture),
                  -EINVAL);
    zassert_equal(capture.count, 0u);
}

ZTEST_SUITE(ccsds_tc_segment, NULL, NULL, NULL, NULL, NULL);
