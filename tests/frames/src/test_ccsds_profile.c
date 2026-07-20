#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include "ccsds/ccsds_bch.h"
#include "ccsds/ccsds_profile.h"
#include "ccsds/ccsds_tc_segment.h"
#include "ccsds/ccsds_udp.h"

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -EINVAL;
}

static int decode_hex_fixture(const char *hex, uint8_t *buf, size_t buf_cap,
                              size_t *buf_len)
{
    size_t hex_len;

    if (!hex || !buf || !buf_len) {
        return -EINVAL;
    }

    hex_len = strlen(hex);
    if ((hex_len % 2u) != 0u) {
        return -EINVAL;
    }

    if (buf_cap < (hex_len / 2u)) {
        return -ENOSPC;
    }

    for (size_t i = 0u; i < hex_len; i += 2u) {
        int high = hex_nibble(hex[i]);
        int low = hex_nibble(hex[i + 1u]);

        if (high < 0 || low < 0) {
            return -EINVAL;
        }

        buf[i / 2u] = (uint8_t)((high << 4) | low);
    }

    *buf_len = hex_len / 2u;
    return 0;
}

static void profile_setup(void *fixture)
{
    ARG_UNUSED(fixture);

    ccsds_profile_tc_rx_reset_stats();
}

static const char short_data_cltu_hex[] =
    "eb90007b00191fc0186410c006000b100e16020000010319008800bbe915465555d2c5c5c5c5c5c5c579";
#define TEST_SHORT_DATA_FSN 0x1fu
#define TEST_COP1_HALF_WINDOW (CONFIG_AKIRA_CCSDS_COP1_WINDOW_SIZE / 2u)
#define TEST_TC_HDR_LEN 5u
#define TEST_SEG_HDR(boundary, map_id) \
    (uint8_t)((((uint8_t)(boundary) & 0x03u) << 6) | ((map_id) & 0x3fu))

struct packet_capture {
    uint16_t apid;
    uint8_t payload[32];
    size_t payload_len;
    uint32_t count;
};

static int capture_profile_packet_handler(
    const struct ccsds_space_packet *packet, void *user_data)
{
    struct packet_capture *capture = user_data;

    zassert_not_null(packet);
    zassert_not_null(capture);
    zassert_true(packet->payload_len <= sizeof(capture->payload));

    capture->apid = packet->apid;
    capture->payload_len = packet->payload_len;
    memcpy(capture->payload, packet->payload, packet->payload_len);
    capture->count++;

    return 0;
}

static void build_space_packet(uint8_t *buf, size_t cap, size_t *len,
                               uint16_t apid, const uint8_t *payload,
                               size_t payload_len)
{
    struct ccsds_space_packet packet = {
        .version = 0u,
        .type = CCSDS_PACKET_TYPE_TC,
        .secondary_header = false,
        .apid = apid,
        .sequence_flags = CCSDS_SEQUENCE_UNSEGMENTED,
        .sequence_count = 7u,
        .payload = payload,
        .payload_len = payload_len,
    };

    zassert_ok(ccsds_space_packet_encode(&packet, buf, cap, len));
}

ZTEST(ccsds_profile, test_packet_unit_dispatch_reaches_registered_apid)
{
    enum {
        TEST_APID = 0x321u,
    };
    static const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    struct ccsds_router router;
    struct packet_capture capture = {0};
    uint8_t packet[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + sizeof(payload)];
    size_t packet_len = 0u;

    ccsds_router_init(&router);
    zassert_ok(ccsds_router_register_apid(
        &router, TEST_APID, capture_profile_packet_handler, &capture));
    build_space_packet(packet, sizeof(packet), &packet_len, TEST_APID,
                       payload, sizeof(payload));

    zassert_ok(ccsds_profile_packet_dispatch(&router, packet, packet_len));
    zassert_equal(capture.count, 1u);
    zassert_equal(capture.apid, TEST_APID);
    zassert_equal(capture.payload_len, sizeof(payload));
    zassert_mem_equal(capture.payload, payload, sizeof(payload));
}

ZTEST(ccsds_profile, test_packet_unit_malformed_input_does_not_dispatch)
{
    enum {
        TEST_APID = 0x322u,
    };
    struct ccsds_router router;
    struct packet_capture capture = {0};
    uint8_t short_packet[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN - 1u] = {0};

    ccsds_router_init(&router);
    zassert_ok(ccsds_router_register_apid(
        &router, TEST_APID, capture_profile_packet_handler, &capture));

    zassert_equal(ccsds_profile_packet_dispatch(&router, short_packet,
                                               sizeof(short_packet)),
                  -EINVAL);
    zassert_equal(capture.count, 0u);
}

ZTEST(ccsds_profile, test_packet_unit_unregistered_apid_returns_no_entry)
{
    enum {
        TEST_APID = 0x323u,
    };
    static const uint8_t payload[] = {0x01};
    struct ccsds_router router;
    uint8_t packet[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + sizeof(payload)];
    size_t packet_len = 0u;

    ccsds_router_init(&router);
    build_space_packet(packet, sizeof(packet), &packet_len, TEST_APID,
                       payload, sizeof(payload));

    zassert_equal(ccsds_profile_packet_dispatch(&router, packet, packet_len),
                  -ENOENT);
}

static void build_tc_frame(uint8_t *buf, size_t len, uint16_t scid,
                           uint8_t vcid, uint8_t fsn)
{
    uint16_t frame_len_field = (uint16_t)(len - 1u);

    memset(buf, 0, len);
    buf[0] = (uint8_t)((scid >> 8) & 0x03u);
    buf[1] = (uint8_t)scid;
    buf[2] = (uint8_t)(((vcid & 0x3fu) << 2) |
                       ((frame_len_field >> 8) & 0x03u));
    buf[3] = (uint8_t)frame_len_field;
    buf[4] = fsn;
}

static void build_tc_packet(uint8_t *buf, size_t payload_len, uint16_t apid,
                            uint8_t seed)
{
    uint16_t length_field = (uint16_t)(payload_len - 1u);

    memset(buf, 0, CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + payload_len);
    buf[0] = (uint8_t)(0x10u | ((apid >> 8) & 0x07u));
    buf[1] = (uint8_t)apid;
    buf[2] = (uint8_t)(CCSDS_SEQUENCE_UNSEGMENTED << 6);
    buf[4] = (uint8_t)(length_field >> 8);
    buf[5] = (uint8_t)length_field;

    for (size_t i = 0u; i < payload_len; i++) {
        buf[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + i] = seed + (uint8_t)i;
    }
}

static void encode_bch_block(const uint8_t data[CCSDS_BCH_DATA_SIZE],
                             uint8_t block[CCSDS_BCH_BLOCK_SIZE])
{
    uint8_t decoded[CCSDS_BCH_DATA_SIZE];
    int corrected_bit;

    memcpy(block, data, CCSDS_BCH_DATA_SIZE);
    for (uint16_t parity = 0u; parity <= UINT8_MAX; parity++) {
        block[CCSDS_BCH_DATA_SIZE] = (uint8_t)parity;
        if (ccsds_bch_decode_block(block, decoded, &corrected_bit) ==
                CCSDS_BCH_OK &&
            memcmp(decoded, data, CCSDS_BCH_DATA_SIZE) == 0) {
            return;
        }
    }

    zassert_unreachable("no BCH parity byte found");
}

static void encode_frame_cltu(const uint8_t *frame, size_t frame_len,
                              uint8_t *cltu, size_t cltu_cap,
                              size_t *cltu_len)
{
    static const uint8_t tail[CCSDS_BCH_BLOCK_SIZE] = {
        0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0x79,
    };
    uint8_t block_data[CCSDS_BCH_DATA_SIZE];
    size_t block_count =
        (frame_len + CCSDS_BCH_DATA_SIZE - 1u) / CCSDS_BCH_DATA_SIZE;
    size_t needed = 2u + (block_count * CCSDS_BCH_BLOCK_SIZE) +
                    CCSDS_BCH_BLOCK_SIZE;

    zassert_true(needed <= cltu_cap);

    cltu[0] = 0xebu;
    cltu[1] = 0x90u;

    for (size_t block = 0u; block < block_count; block++) {
        size_t frame_offset = block * CCSDS_BCH_DATA_SIZE;
        size_t remaining = frame_len - frame_offset;
        size_t copy_len = MIN(remaining, CCSDS_BCH_DATA_SIZE);

        memset(block_data, 0x55, sizeof(block_data));
        memcpy(block_data, &frame[frame_offset], copy_len);
        encode_bch_block(block_data,
                         &cltu[2u + (block * CCSDS_BCH_BLOCK_SIZE)]);
    }

    memcpy(&cltu[2u + (block_count * CCSDS_BCH_BLOCK_SIZE)], tail,
           sizeof(tail));
    *cltu_len = needed;
}

static void build_tc_segment_cltu(enum ccsds_tc_segment_boundary boundary,
                                  uint8_t map_id, const uint8_t *segment_data,
                                  size_t segment_data_len, uint8_t fsn,
                                  uint8_t *cltu, size_t cltu_cap,
                                  size_t *cltu_len)
{
    uint8_t frame[TEST_TC_HDR_LEN + CCSDS_TC_SEGMENT_HDR_LEN + 32u];
    size_t frame_len = TEST_TC_HDR_LEN + CCSDS_TC_SEGMENT_HDR_LEN +
                       segment_data_len;

    zassert_true(frame_len <= sizeof(frame));
    build_tc_frame(frame, frame_len, CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 0u,
                   fsn);
    frame[TEST_TC_HDR_LEN] = TEST_SEG_HDR(boundary, map_id);
    memcpy(&frame[TEST_TC_HDR_LEN + CCSDS_TC_SEGMENT_HDR_LEN], segment_data,
           segment_data_len);
    encode_frame_cltu(frame, frame_len, cltu, cltu_cap, cltu_len);
}

static void build_empty_segment_cltu(uint16_t scid, uint8_t vcid, uint8_t fsn,
                                     uint8_t *cltu, size_t cltu_cap,
                                     size_t *cltu_len)
{
    uint8_t frame[TEST_TC_HDR_LEN + CCSDS_TC_SEGMENT_HDR_LEN];

    build_tc_frame(frame, sizeof(frame), scid, vcid, fsn);
    frame[TEST_TC_HDR_LEN] = TEST_SEG_HDR(CCSDS_TC_SEGMENT_UNSEGMENTED, 0u);
    encode_frame_cltu(frame, sizeof(frame), cltu, cltu_cap, cltu_len);
}

static int capture_packet_handler(const struct ccsds_space_packet *packet,
                                  void *user_data)
{
    struct packet_capture *capture = user_data;

    capture->apid = packet->apid;
    capture->payload_len = packet->payload_len;
    zassert_true(packet->payload_len <= sizeof(capture->payload));
    memcpy(capture->payload, packet->payload, packet->payload_len);
    capture->count++;

    return 0;
}

ZTEST(ccsds_profile, test_tc_dispatch_accepts_unlock_control_frame)
{
    static const char unlock_cltu_hex[] =
        "eb90307b0007000055f07555555555555522c5c5c5c5c5c5c579";
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_tc_rx_stats stats;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(unlock_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.lockout_flag = true;
    profile.vc_state.retransmit_flag = true;

    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
    zassert_false(profile.vc_state.lockout_flag);
    zassert_false(profile.vc_state.retransmit_flag);

    ccsds_profile_tc_rx_get_stats(&stats);
    zassert_equal(stats.cltus_received, 1u);
    zassert_equal(stats.control_frames_seen, 1u);
    zassert_equal(stats.packets_dispatched, 0u);
    zassert_equal(stats.dispatch_failures, 0u);
    zassert_equal(stats.last_error, 0);
}

ZTEST(ccsds_profile, test_configured_unit_dispatch_uses_complete_cltu_path)
{
    static const char unlock_cltu_hex[] =
        "eb90307b0007000055f07555555555555522c5c5c5c5c5c5c579";
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_input input;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(unlock_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.lockout_flag = true;
    profile.vc_state.retransmit_flag = true;
    ccsds_profile_input_init(&input, &router, &profile);

    zassert_ok(ccsds_profile_input_dispatch_unit(&input, cltu, cltu_len));
    zassert_false(profile.vc_state.lockout_flag);
    zassert_false(profile.vc_state.retransmit_flag);
}

ZTEST(ccsds_profile, test_udp_datagram_handoff_uses_configured_input_path)
{
    static const char unlock_cltu_hex[] =
        "eb90307b0007000055f07555555555555522c5c5c5c5c5c5c579";
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_input input;
    struct ccsds_udp_stats stats_before;
    struct ccsds_udp_stats stats_after;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(unlock_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    ccsds_profile_input_init(&input, &router, &profile);
    profile.vc_state.lockout_flag = true;

    ccsds_udp_get_stats(&stats_before);
    zassert_ok(ccsds_udp_dispatch_datagram(&input, cltu, cltu_len));
    ccsds_udp_get_stats(&stats_after);

    zassert_false(profile.vc_state.lockout_flag);
    zassert_equal(stats_after.datagrams_received,
                  stats_before.datagrams_received + 1u);
}

ZTEST(ccsds_profile, test_tc_dispatch_accepts_set_vr_control_frame)
{
    static const char set_vr_cltu_hex[] =
        "eb90307b00090082002a1fa63455555555a2c5c5c5c5c5c5c579";
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_tc_rx_stats stats;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(set_vr_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.retransmit_flag = true;

    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
    zassert_equal(profile.vc_state.report_value, 0x1fu);
    zassert_false(profile.vc_state.retransmit_flag);

    ccsds_profile_tc_rx_get_stats(&stats);
    zassert_equal(stats.cltus_received, 1u);
    zassert_equal(stats.control_frames_seen, 1u);
    zassert_equal(stats.packets_dispatched, 0u);
    zassert_equal(stats.dispatch_failures, 0u);
    zassert_equal(stats.last_error, 0);
}

ZTEST(ccsds_profile, test_tc_dispatch_rejects_set_vr_during_lockout)
{
    static const char set_vr_cltu_hex[] =
        "eb90307b00090082002a1fa63455555555a2c5c5c5c5c5c5c579";
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(set_vr_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.lockout_flag = true;
    profile.vc_state.report_value = 0x10u;
    profile.vc_state.farm_b_counter = 2u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EACCES);
    zassert_true(profile.vc_state.lockout_flag);
    zassert_equal(profile.vc_state.report_value, 0x10u);
    zassert_equal(profile.vc_state.farm_b_counter, 3u);
}

ZTEST(ccsds_profile, test_tc_dispatch_advances_expected_fsn)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.report_value = 0x1fu;
    profile.vc_state.retransmit_flag = true;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -ENOENT);
    zassert_equal(profile.vc_state.report_value, 0x20u);
    zassert_false(profile.vc_state.retransmit_flag);
}

ZTEST(ccsds_profile, test_tc_dispatch_advances_farm_b_after_scid_vc_accept)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.report_value = TEST_SHORT_DATA_FSN;
    profile.vc_state.farm_b_counter = 3u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -ENOENT);
    zassert_equal(profile.vc_state.farm_b_counter, 0u);
}

ZTEST(ccsds_profile, test_tc_dispatch_does_not_advance_farm_b_on_cltu_reject)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    build_empty_segment_cltu(CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 0u, 0u, cltu,
                             sizeof(cltu), &cltu_len);
    cltu[0] = 0x00u;

    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.farm_b_counter = 2u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EINVAL);
    zassert_equal(profile.vc_state.farm_b_counter, 2u);
}

ZTEST(ccsds_profile, test_tc_dispatch_does_not_advance_farm_b_on_wrong_scid)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;
    uint16_t wrong_scid = (CONFIG_AKIRA_CCSDS_SPACECRAFT_ID + 1u) & 0x03ffu;

    build_empty_segment_cltu(wrong_scid, 0u, 0u, cltu, sizeof(cltu),
                             &cltu_len);
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.farm_b_counter = 2u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EACCES);
    zassert_equal(profile.vc_state.farm_b_counter, 2u);
}

ZTEST(ccsds_profile, test_tc_dispatch_does_not_advance_farm_b_on_wrong_vc)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    build_empty_segment_cltu(CONFIG_AKIRA_CCSDS_SPACECRAFT_ID, 1u, 0u, cltu,
                             sizeof(cltu), &cltu_len);
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.farm_b_counter = 2u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EACCES);
    zassert_equal(profile.vc_state.farm_b_counter, 2u);
}

ZTEST(ccsds_profile, test_tc_dispatch_reassembles_segmented_packet)
{
    enum {
        TEST_APID = 0x123u,
        TEST_MAP_ID = 5u,
        TEST_PACKET_PAYLOAD_LEN = 10u,
    };
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_tc_rx_stats stats;
    struct packet_capture capture = {0};
    uint8_t packet[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN +
                   TEST_PACKET_PAYLOAD_LEN];
    uint8_t cltu[3][CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len[3] = {0};

    build_tc_packet(packet, TEST_PACKET_PAYLOAD_LEN, TEST_APID, 0x40u);
    build_tc_segment_cltu(CCSDS_TC_SEGMENT_FIRST, TEST_MAP_ID, packet, 10u,
                          0u, cltu[0], sizeof(cltu[0]), &cltu_len[0]);
    build_tc_segment_cltu(CCSDS_TC_SEGMENT_CONTINUATION, TEST_MAP_ID,
                          &packet[10], 3u, 1u, cltu[1], sizeof(cltu[1]),
                          &cltu_len[1]);
    build_tc_segment_cltu(CCSDS_TC_SEGMENT_LAST, TEST_MAP_ID, &packet[13], 3u,
                          2u, cltu[2], sizeof(cltu[2]), &cltu_len[2]);

    ccsds_router_init(&router);
    zassert_ok(ccsds_router_register_apid(&router, TEST_APID,
                                          capture_packet_handler, &capture));
    ccsds_profile_tc_rx_init(&profile, &router);

    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu[0],
                                              cltu_len[0]));
    zassert_equal(capture.count, 0u);
    zassert_true(profile.reassembly.active);
    zassert_equal(profile.reassembly.map_id, TEST_MAP_ID);
    zassert_equal(profile.reassembly.expected_len, sizeof(packet));

    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu[1],
                                              cltu_len[1]));
    zassert_equal(capture.count, 0u);
    zassert_true(profile.reassembly.active);

    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu[2],
                                              cltu_len[2]));
    zassert_false(profile.reassembly.active);
    zassert_equal(capture.count, 1u);
    zassert_equal(capture.apid, TEST_APID);
    zassert_equal(capture.payload_len, TEST_PACKET_PAYLOAD_LEN);
    zassert_mem_equal(capture.payload,
                      &packet[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN],
                      TEST_PACKET_PAYLOAD_LEN);

    ccsds_profile_tc_rx_get_stats(&stats);
    zassert_equal(stats.cltus_received, 3u);
    zassert_equal(stats.packets_dispatched, 1u);
    zassert_equal(stats.dispatch_failures, 0u);
}

ZTEST(ccsds_profile, test_tc_dispatch_rejects_data_frame_during_lockout)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.lockout_flag = true;
    profile.vc_state.report_value = TEST_SHORT_DATA_FSN;
    profile.vc_state.farm_b_counter = 1u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EACCES);
    zassert_true(profile.vc_state.lockout_flag);
    zassert_equal(profile.vc_state.report_value, TEST_SHORT_DATA_FSN);
    zassert_equal(profile.vc_state.farm_b_counter, 2u);
}

ZTEST(ccsds_profile, test_tc_dispatch_requests_retransmit_on_fsn_jump)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.report_value = (uint8_t)(TEST_SHORT_DATA_FSN - 1u);
    profile.vc_state.farm_b_counter = 2u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EAGAIN);
    zassert_equal(profile.vc_state.report_value,
                  (uint8_t)(TEST_SHORT_DATA_FSN - 1u));
    zassert_true(profile.vc_state.retransmit_flag);
    zassert_false(profile.vc_state.lockout_flag);
    zassert_equal(profile.vc_state.farm_b_counter, 3u);
}

ZTEST(ccsds_profile, test_tc_dispatch_discards_prior_fsn_without_retransmit)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.report_value = (uint8_t)(TEST_SHORT_DATA_FSN + 1u);
    profile.vc_state.farm_b_counter = 3u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EAGAIN);
    zassert_equal(profile.vc_state.report_value,
                  (uint8_t)(TEST_SHORT_DATA_FSN + 1u));
    zassert_false(profile.vc_state.retransmit_flag);
    zassert_false(profile.vc_state.lockout_flag);
    zassert_equal(profile.vc_state.farm_b_counter, 0u);
}

ZTEST(ccsds_profile, test_tc_dispatch_locks_out_on_fsn_window_boundary)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    profile.vc_state.report_value =
        (uint8_t)(TEST_SHORT_DATA_FSN - TEST_COP1_HALF_WINDOW);
    profile.vc_state.farm_b_counter = 0u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EAGAIN);
    zassert_equal(profile.vc_state.report_value,
                  (uint8_t)(TEST_SHORT_DATA_FSN - TEST_COP1_HALF_WINDOW));
    zassert_false(profile.vc_state.retransmit_flag);
    zassert_true(profile.vc_state.lockout_flag);
    zassert_equal(profile.vc_state.farm_b_counter, 1u);
}

ZTEST(ccsds_profile, test_tc_build_clcw_packs_report_fields)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint32_t clcw;

    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    zassert_ok(ccsds_profile_tc_set_accepted_vcid(&profile, 3u));

    profile.vc_state.no_rf_available_flag = true;
    profile.vc_state.no_bit_lock_flag = true;
    profile.vc_state.lockout_flag = true;
    profile.vc_state.wait_flag = true;
    profile.vc_state.retransmit_flag = true;
    profile.vc_state.farm_b_counter = 2u;
    profile.vc_state.report_value = 0x5au;

    zassert_ok(ccsds_profile_tc_build_clcw(&profile, &clcw));
    zassert_equal(clcw, 0x010cfc5au);
}

ZTEST(ccsds_profile, test_tc_set_accepted_vcid_rejects_invalid_vc)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;

    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);

    zassert_equal(ccsds_profile_tc_set_accepted_vcid(&profile,
                                                     CCSDS_TC_VC_COUNT),
                  -EINVAL);
}

ZTEST_SUITE(ccsds_profile, NULL, NULL, profile_setup, NULL, NULL);
