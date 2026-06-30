#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include "ccsds/ccsds_tc_frame.h"

#define TEST_TC_HDR_LEN 5u

static void build_tc_frame(uint8_t *buf, size_t len, uint16_t scid,
                           uint8_t vcid, bool bypass, bool control,
                           uint8_t fsn)
{
    uint16_t frame_len_field = (uint16_t)(len - 1u);

    memset(buf, 0, len);
    buf[0] = (uint8_t)((bypass ? BIT(5) : 0u) |
                       (control ? BIT(4) : 0u) |
                       ((scid >> 8) & 0x03u));
    buf[1] = (uint8_t)scid;
    buf[2] = (uint8_t)(((vcid & 0x3fu) << 2) |
                       ((frame_len_field >> 8) & 0x03u));
    buf[3] = (uint8_t)frame_len_field;
    buf[4] = fsn;
}

ZTEST(ccsds_tc_frame, test_decode_rejects_short_frame)
{
    uint8_t frame_bytes[TEST_TC_HDR_LEN - 1u] = {0};
    struct ccsds_tc_frame frame;

    zassert_equal(ccsds_tc_frame_decode(frame_bytes, sizeof(frame_bytes),
                                        &frame),
                  -EINVAL);
}

ZTEST(ccsds_tc_frame, test_decode_rejects_nonzero_version)
{
    uint8_t frame_bytes[TEST_TC_HDR_LEN];
    struct ccsds_tc_frame frame;

    build_tc_frame(frame_bytes, sizeof(frame_bytes),
                   CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 0u, false, false, 0u);
    frame_bytes[0] |= BIT(6);

    zassert_equal(ccsds_tc_frame_decode(frame_bytes, sizeof(frame_bytes),
                                        &frame),
                  -EINVAL);
}

ZTEST(ccsds_tc_frame, test_decode_rejects_length_mismatch)
{
    uint8_t frame_bytes[TEST_TC_HDR_LEN + 1u];
    struct ccsds_tc_frame frame;

    build_tc_frame(frame_bytes, sizeof(frame_bytes),
                   CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 0u, false, false, 0u);
    frame_bytes[3]--;

    zassert_equal(ccsds_tc_frame_decode(frame_bytes, sizeof(frame_bytes),
                                        &frame),
                  -EMSGSIZE);
}

ZTEST(ccsds_tc_frame, test_decode_accepts_cltu_fill_after_frame)
{
    uint8_t frame_bytes[TEST_TC_HDR_LEN + 7u];
    struct ccsds_tc_frame frame;

    build_tc_frame(frame_bytes, TEST_TC_HDR_LEN + 3u,
                   CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 2u, false, false,
                   0x24u);
    frame_bytes[5] = 0x11u;
    frame_bytes[6] = 0x22u;
    frame_bytes[7] = 0x33u;
    memset(&frame_bytes[8], 0x55, 4u);

    zassert_ok(ccsds_tc_frame_decode(frame_bytes, sizeof(frame_bytes),
                                     &frame));
    zassert_equal(frame.virtual_channel_id, 2u);
    zassert_equal(frame.frame_sequence_number, 0x24u);
    zassert_equal(frame.data_len, 3u);
    zassert_mem_equal(frame.data, &frame_bytes[TEST_TC_HDR_LEN],
                      frame.data_len);
}

ZTEST(ccsds_tc_frame, test_decode_rejects_wrong_spacecraft_id)
{
    uint8_t frame_bytes[TEST_TC_HDR_LEN];
    struct ccsds_tc_frame frame;
    uint16_t wrong_scid = (CONFIG_AKIRA_CCSDS_SPACECRAFT_ID + 1u) & 0x03ffu;

    build_tc_frame(frame_bytes, sizeof(frame_bytes), wrong_scid, 0u, false,
                   false, 0u);

    zassert_equal(ccsds_tc_frame_decode(frame_bytes, sizeof(frame_bytes),
                                        &frame),
                  -EACCES);
}

ZTEST(ccsds_tc_frame, test_decode_data_frame_fields)
{
    uint8_t frame_bytes[TEST_TC_HDR_LEN + 3u];
    struct ccsds_tc_frame frame;

    build_tc_frame(frame_bytes, sizeof(frame_bytes),
                   CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 17u, false, false,
                   0x42u);
    frame_bytes[5] = 0xaau;
    frame_bytes[6] = 0xbbu;
    frame_bytes[7] = 0xccu;

    zassert_ok(ccsds_tc_frame_decode(frame_bytes, sizeof(frame_bytes),
                                     &frame));
    zassert_equal(frame.spacecraft_id, CONFIG_AKIRA_CCSDS_SPACECRAFT_ID);
    zassert_equal(frame.virtual_channel_id, 17u);
    zassert_false(frame.bypass);
    zassert_false(frame.control_command);
    zassert_equal(frame.frame_sequence_number, 0x42u);
    zassert_equal(frame.data_len, 3u);
    zassert_equal(frame.data, &frame_bytes[TEST_TC_HDR_LEN]);
    zassert_mem_equal(frame.data, &frame_bytes[TEST_TC_HDR_LEN],
                      frame.data_len);
}

ZTEST(ccsds_tc_frame, test_decode_control_frame_fields)
{
    uint8_t frame_bytes[TEST_TC_HDR_LEN + 2u];
    struct ccsds_tc_frame frame;

    build_tc_frame(frame_bytes, sizeof(frame_bytes),
                   CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 63u, true, true, 0x7eu);
    frame_bytes[5] = 0x01u;
    frame_bytes[6] = 0x02u;

    zassert_ok(ccsds_tc_frame_decode(frame_bytes, sizeof(frame_bytes),
                                     &frame));
    zassert_equal(frame.virtual_channel_id, 63u);
    zassert_true(frame.bypass);
    zassert_true(frame.control_command);
    zassert_equal(frame.frame_sequence_number, 0x7eu);
    zassert_equal(frame.data_len, 2u);
    zassert_equal(frame.data, &frame_bytes[TEST_TC_HDR_LEN]);
}

ZTEST_SUITE(ccsds_tc_frame, NULL, NULL, NULL, NULL, NULL);
