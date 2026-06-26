#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include "ccsds/ccsds_crc16.h"
#include "ccsds/ccsds_rs.h"
#include "ccsds/ccsds_tm_frame.h"

bool ccsds_tm_frame_test_is_running(void);
bool ccsds_tm_frame_test_run_cycle(k_timeout_t *next_delay, uint8_t *vcid);

#define TEST_TM_ASM_LEN 4u
#define TEST_TM_PRIMARY_HDR_LEN 6u
#define TEST_TM_OCF_LEN 4u
#define TEST_TM_IDLE_VC_ID 7u
#define TEST_TM_IDLE_FHP 0x7feu
#define TEST_TM_NO_FHP 0x7ffu
#define TEST_TM_ACTIVE_FHP 0u
#define TEST_TM_SEC_HDR_FLAG 0u
#define TEST_TM_SYNC_FLAG 0u
#define TEST_TM_PACKET_ORDER_FLAG 0u
#define TEST_TM_SEGMENT_LENGTH_ID 3u
#define TEST_TM_WORD2_IDLE \
    ((TEST_TM_SEC_HDR_FLAG << 15) | (TEST_TM_SYNC_FLAG << 14) | \
     (TEST_TM_PACKET_ORDER_FLAG << 13) | (TEST_TM_SEGMENT_LENGTH_ID << 11) | \
     TEST_TM_IDLE_FHP)
#define TEST_TM_WORD2_ACTIVE \
    ((TEST_TM_SEC_HDR_FLAG << 15) | (TEST_TM_SYNC_FLAG << 14) | \
     (TEST_TM_PACKET_ORDER_FLAG << 13) | (TEST_TM_SEGMENT_LENGTH_ID << 11) | \
     TEST_TM_ACTIVE_FHP)
#define TEST_TM_IDLE_APID 0x07ffu
#define TEST_TM_ASM0 0x1au
#define TEST_TM_ASM1 0xcfu
#define TEST_TM_ASM2 0xfcu
#define TEST_TM_ASM3 0x1du

#ifdef CONFIG_AKIRA_CCSDS_RS
#define TEST_TM_FRAME_LEN CCSDS_RS_INTERLEAVED_DATA_LEN
#define TEST_TM_CODED_LEN \
    (TEST_TM_ASM_LEN + TEST_TM_FRAME_LEN + CCSDS_RS_INTERLEAVED_PARITY_LEN)
#define TEST_TM_FRAME_OFFSET TEST_TM_ASM_LEN
#else
#define TEST_TM_FRAME_LEN CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN
#define TEST_TM_CODED_LEN TEST_TM_FRAME_LEN
#define TEST_TM_FRAME_OFFSET 0u
#endif

#ifdef CONFIG_AKIRA_CCSDS_TM_FECF
#define TEST_TM_FECF_LEN CCSDS_CRC16_LEN
#else
#define TEST_TM_FECF_LEN 0u
#endif

struct tm_capture {
    uint8_t vcid;
    uint8_t frame[TEST_TM_CODED_LEN];
    size_t len;
    uint8_t calls;
};

static int capture_route(uint8_t vcid, const uint8_t *frame, size_t frame_len,
                         void *user_data)
{
    struct tm_capture *capture = user_data;

    zassert_not_null(capture);
    zassert_not_null(frame);
    zassert_true(frame_len <= sizeof(capture->frame));

    capture->vcid = vcid;
    capture->len = frame_len;
    capture->calls++;
    memcpy(capture->frame, frame, frame_len);

    return 0;
}

static uint16_t read_be16(const uint8_t *buf)
{
    return ((uint16_t)buf[0] << 8) | buf[1];
}

static void write_be16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value >> 8);
    buf[1] = (uint8_t)value;
}

static void build_test_packet(uint8_t *packet, size_t packet_len,
                              uint16_t apid, uint8_t seed)
{
    zassert_true(packet_len >= 7u);

    write_be16(&packet[0], apid & CCSDS_APID_MAX);
    write_be16(&packet[2], (uint16_t)CCSDS_SEQUENCE_UNSEGMENTED << 14);
    write_be16(&packet[4],
               (uint16_t)(packet_len - TEST_TM_PRIMARY_HDR_LEN - 1u));

    for (size_t i = TEST_TM_PRIMARY_HDR_LEN; i < packet_len; i++) {
        packet[i] = seed + (uint8_t)i;
    }
}

static void tm_frame_setup(void *fixture)
{
    ARG_UNUSED(fixture);

    zassert_ok(ccsds_tm_frame_init());
}

ZTEST(ccsds_tm_frame, test_start_stop_updates_generator_state)
{
    zassert_false(ccsds_tm_frame_test_is_running());

    zassert_ok(ccsds_tm_frame_start(K_MSEC(5), K_MSEC(50)));
    zassert_true(ccsds_tm_frame_test_is_running());

    zassert_ok(ccsds_tm_frame_stop());
    zassert_false(ccsds_tm_frame_test_is_running());
}

ZTEST(ccsds_tm_frame, test_idle_cycle_uses_idle_delay)
{
    k_timeout_t next_delay;
    uint8_t vcid;
    bool active;

    zassert_ok(ccsds_tm_frame_start(K_MSEC(5), K_MSEC(50)));

    active = ccsds_tm_frame_test_run_cycle(&next_delay, &vcid);

    zassert_false(active);
    zassert_equal(vcid, 7u);
    zassert_true(K_TIMEOUT_EQ(next_delay, K_MSEC(50)));

    zassert_ok(ccsds_tm_frame_stop());
}

ZTEST(ccsds_tm_frame, test_idle_cycle_emits_one_routed_output)
{
    struct tm_capture capture = {0};
    k_timeout_t next_delay;
    uint8_t vcid;
    bool active;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(TEST_TM_IDLE_VC_ID,
                                           CCSDS_TM_ROUTE_ARCHIVE));

    active = ccsds_tm_frame_test_run_cycle(&next_delay, &vcid);

    zassert_false(active);
    zassert_equal(vcid, TEST_TM_IDLE_VC_ID);
    zassert_equal(capture.calls, 1u);
    zassert_equal(capture.vcid, TEST_TM_IDLE_VC_ID);
    zassert_equal(capture.len, TEST_TM_CODED_LEN);
}

ZTEST(ccsds_tm_frame, test_idle_output_header_and_zero_ocf)
{
    struct tm_capture capture = {0};
    const uint8_t *tm_frame;
    uint16_t word0;
    uint16_t word2;
    size_t data_len;
    size_t ocf_offset;
    uint8_t expected_mcfc;
    uint8_t expected_vcfc;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(TEST_TM_IDLE_VC_ID,
                                           CCSDS_TM_ROUTE_ARCHIVE));

    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    word0 = read_be16(&tm_frame[0]);
    word2 = read_be16(&tm_frame[4]);
    data_len = TEST_TM_FRAME_LEN - TEST_TM_PRIMARY_HDR_LEN - TEST_TM_OCF_LEN -
               TEST_TM_FECF_LEN;
    ocf_offset = TEST_TM_PRIMARY_HDR_LEN + data_len;
    expected_mcfc = 0u;
    expected_vcfc = 0u;

    zassert_equal((word0 >> 14) & 0x3u, 0u);
    zassert_equal((word0 >> 4) & 0x3ffu,
                  CONFIG_AKIRA_CCSDS_SPACECRAFT_ID);
    zassert_equal((word0 >> 1) & 0x7u, TEST_TM_IDLE_VC_ID);
    zassert_equal(word0 & 0x1u, 1u);
    zassert_equal(tm_frame[2], expected_mcfc);
    zassert_equal(tm_frame[3], expected_vcfc);
    zassert_equal(word2, TEST_TM_WORD2_IDLE);
    zassert_equal(word2 & 0x7ffu, TEST_TM_IDLE_FHP);

    for (size_t i = 0u; i < data_len; i++) {
        zassert_equal(tm_frame[TEST_TM_PRIMARY_HDR_LEN + i], 0u);
    }

    for (size_t i = 0u; i < TEST_TM_OCF_LEN; i++) {
        zassert_equal(tm_frame[ocf_offset + i], 0u);
    }
}

ZTEST(ccsds_tm_frame, test_idle_output_counters_increment)
{
    struct tm_capture capture = {0};
    const uint8_t *first_frame;
    const uint8_t *second_frame;
    uint8_t first[TEST_TM_CODED_LEN];

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(TEST_TM_IDLE_VC_ID,
                                           CCSDS_TM_ROUTE_ARCHIVE));

    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    memcpy(first, capture.frame, capture.len);
    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    first_frame = &first[TEST_TM_FRAME_OFFSET];
    second_frame = &capture.frame[TEST_TM_FRAME_OFFSET];

    zassert_equal(first_frame[2], 0u);
    zassert_equal(first_frame[3], 0u);
    zassert_equal(second_frame[2], 1u);
    zassert_equal(second_frame[3], 1u);
    zassert_equal(capture.calls, 2u);
}

#ifdef CONFIG_AKIRA_CCSDS_RS
ZTEST(ccsds_tm_frame, test_idle_output_includes_asm_and_rs_parity)
{
    struct tm_capture capture = {0};
    uint8_t expected_parity[CCSDS_RS_INTERLEAVED_PARITY_LEN];
    const uint8_t *tm_frame;
    const uint8_t *parity;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(TEST_TM_IDLE_VC_ID,
                                           CCSDS_TM_ROUTE_ARCHIVE));

    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    parity = &capture.frame[TEST_TM_FRAME_OFFSET + TEST_TM_FRAME_LEN];
    ccsds_rs_encode(tm_frame, expected_parity);

    zassert_equal(capture.frame[0], TEST_TM_ASM0);
    zassert_equal(capture.frame[1], TEST_TM_ASM1);
    zassert_equal(capture.frame[2], TEST_TM_ASM2);
    zassert_equal(capture.frame[3], TEST_TM_ASM3);
    zassert_mem_equal(parity, expected_parity, sizeof(expected_parity));
}
#endif

#ifdef CONFIG_AKIRA_CCSDS_TM_FECF
ZTEST(ccsds_tm_frame, test_idle_output_includes_fecf_before_rs_parity)
{
    struct tm_capture capture = {0};
    const uint8_t *tm_frame;
    size_t fecf_offset = TEST_TM_FRAME_LEN - TEST_TM_FECF_LEN;
    uint16_t expected_fecf;
    uint16_t actual_fecf;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(TEST_TM_IDLE_VC_ID,
                                           CCSDS_TM_ROUTE_ARCHIVE));

    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    expected_fecf = ccsds_crc16_compute(tm_frame, fecf_offset);
    actual_fecf = read_be16(&tm_frame[fecf_offset]);

    zassert_equal(actual_fecf, expected_fecf);
    zassert_true(ccsds_crc16_check(tm_frame, TEST_TM_FRAME_LEN));
}
#endif

ZTEST(ccsds_tm_frame, test_active_cycle_uses_active_delay_and_lowest_vc)
{
    static const uint8_t packet[] = {
        0x08, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xaa
    };
    k_timeout_t next_delay;
    uint8_t vcid;
    bool active;

    zassert_ok(ccsds_tm_frame_add(3u, packet, sizeof(packet), K_NO_WAIT));
    zassert_ok(ccsds_tm_frame_add(1u, packet, sizeof(packet), K_NO_WAIT));
    zassert_ok(ccsds_tm_frame_start(K_MSEC(5), K_MSEC(50)));

    active = ccsds_tm_frame_test_run_cycle(&next_delay, &vcid);

    zassert_true(active);
    zassert_equal(vcid, 1u);
    zassert_true(K_TIMEOUT_EQ(next_delay, K_MSEC(5)));

    zassert_ok(ccsds_tm_frame_stop());
}

ZTEST(ccsds_tm_frame, test_active_cycle_emits_packet_frame_on_selected_route)
{
    static const uint8_t packet[] = {
        0x08, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xaa
    };
    struct tm_capture capture = {0};
    k_timeout_t next_delay;
    uint8_t vcid;
    bool active;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(2u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(2u, packet, sizeof(packet), K_NO_WAIT));

    active = ccsds_tm_frame_test_run_cycle(&next_delay, &vcid);

    zassert_true(active);
    zassert_equal(vcid, 2u);
    zassert_equal(capture.calls, 1u);
    zassert_equal(capture.vcid, 2u);
    zassert_equal(capture.len, TEST_TM_CODED_LEN);
}

ZTEST(ccsds_tm_frame, test_active_output_header_packet_fill_and_zero_ocf)
{
    static const uint8_t packet[] = {
        0x08, 0x23, 0xc0, 0x05, 0x00, 0x01, 0xab, 0xcd
    };
    struct tm_capture capture = {0};
    const uint8_t *tm_frame;
    const uint8_t *data;
    uint16_t word0;
    uint16_t word2;
    size_t data_len;
    size_t ocf_offset;
    uint8_t expected_mcfc = 0u;
    uint8_t expected_vcfc = 0u;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(4u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(4u, packet, sizeof(packet), K_NO_WAIT));

    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    data = &tm_frame[TEST_TM_PRIMARY_HDR_LEN];
    word0 = read_be16(&tm_frame[0]);
    word2 = read_be16(&tm_frame[4]);
    data_len = TEST_TM_FRAME_LEN - TEST_TM_PRIMARY_HDR_LEN - TEST_TM_OCF_LEN -
               TEST_TM_FECF_LEN;
    ocf_offset = TEST_TM_PRIMARY_HDR_LEN + data_len;

    zassert_equal((word0 >> 4) & 0x3ffu,
                  CONFIG_AKIRA_CCSDS_SPACECRAFT_ID);
    zassert_equal((word0 >> 1) & 0x7u, 4u);
    zassert_equal(tm_frame[2], expected_mcfc);
    zassert_equal(tm_frame[3], expected_vcfc);
    zassert_equal(word2, TEST_TM_WORD2_ACTIVE);
    zassert_equal(word2 & 0x7ffu, TEST_TM_ACTIVE_FHP);
    zassert_mem_equal(data, packet, sizeof(packet));

    zassert_equal(read_be16(&data[sizeof(packet)]) & TEST_TM_IDLE_APID,
                  TEST_TM_IDLE_APID);
    zassert_equal(read_be16(&data[sizeof(packet) + 2u]),
                  (uint16_t)CCSDS_SEQUENCE_UNSEGMENTED << 14);
    zassert_equal(read_be16(&data[sizeof(packet) + 4u]),
                  data_len - sizeof(packet) -
                      TEST_TM_PRIMARY_HDR_LEN - 1u);

    for (size_t i = 0u; i < TEST_TM_OCF_LEN; i++) {
        zassert_equal(tm_frame[ocf_offset + i], 0u);
    }
}

ZTEST(ccsds_tm_frame, test_active_output_packs_multiple_queued_packets)
{
    uint8_t first[7u];
    uint8_t second[9u];
    struct tm_capture capture = {0};
    const uint8_t *tm_frame;
    const uint8_t *data;
    size_t second_offset = sizeof(first);

    build_test_packet(first, sizeof(first), 0x11u, 0xa0u);
    build_test_packet(second, sizeof(second), 0x22u, 0xb0u);

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(0u, first, sizeof(first), K_NO_WAIT));
    zassert_ok(ccsds_tm_frame_add(0u, second, sizeof(second), K_NO_WAIT));

    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    data = &tm_frame[TEST_TM_PRIMARY_HDR_LEN];

    zassert_equal(read_be16(&tm_frame[4]) & 0x7ffu, TEST_TM_ACTIVE_FHP);
    zassert_mem_equal(data, first, sizeof(first));
    zassert_mem_equal(&data[second_offset], second, sizeof(second));
    zassert_equal(read_be16(&data[second_offset + sizeof(second)]) &
                      TEST_TM_IDLE_APID,
                  TEST_TM_IDLE_APID);
}

ZTEST(ccsds_tm_frame, test_active_output_continues_packet_across_frames)
{
    uint8_t packet[CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH];
    uint8_t next_packet[7u];
    struct tm_capture capture = {0};
    uint8_t first[TEST_TM_CODED_LEN];
    const uint8_t *first_tm_frame;
    const uint8_t *second_tm_frame;
    const uint8_t *first_data;
    const uint8_t *second_data;
    size_t data_len = TEST_TM_FRAME_LEN - TEST_TM_PRIMARY_HDR_LEN -
                      TEST_TM_OCF_LEN - TEST_TM_FECF_LEN;
    size_t packet_len = data_len + 10u;
    size_t second_frame_tail_len = packet_len - data_len;

    build_test_packet(packet, packet_len, 0x33u, 0xc0u);
    build_test_packet(next_packet, sizeof(next_packet), 0x34u, 0xe0u);

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(0u, packet, packet_len, K_NO_WAIT));
    zassert_ok(ccsds_tm_frame_add(0u, next_packet, sizeof(next_packet),
                                  K_NO_WAIT));

    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    memcpy(first, capture.frame, capture.len);
    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    first_tm_frame = &first[TEST_TM_FRAME_OFFSET];
    second_tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    first_data = &first_tm_frame[TEST_TM_PRIMARY_HDR_LEN];
    second_data = &second_tm_frame[TEST_TM_PRIMARY_HDR_LEN];

    zassert_equal(read_be16(&first_tm_frame[4]) & 0x7ffu,
                  TEST_TM_ACTIVE_FHP);
    zassert_mem_equal(first_data, packet, data_len);

    zassert_mem_equal(second_data, &packet[data_len], second_frame_tail_len);
    zassert_equal(read_be16(&second_tm_frame[4]) & 0x7ffu,
                  second_frame_tail_len);
    zassert_mem_equal(&second_data[second_frame_tail_len], next_packet,
                      sizeof(next_packet));
    zassert_equal(read_be16(&second_data[second_frame_tail_len +
                                         sizeof(next_packet)]) &
                      TEST_TM_IDLE_APID,
                  TEST_TM_IDLE_APID);
}

ZTEST(ccsds_tm_frame, test_active_output_marks_no_packet_start_for_full_continuation)
{
    uint8_t packet[CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH];
    struct tm_capture capture = {0};
    const uint8_t *second_tm_frame;
    size_t data_len = TEST_TM_FRAME_LEN - TEST_TM_PRIMARY_HDR_LEN -
                      TEST_TM_OCF_LEN - TEST_TM_FECF_LEN;
    size_t packet_len = data_len * 2u;

    zassert_true(packet_len <= sizeof(packet));
    build_test_packet(packet, packet_len, 0x44u, 0xd0u);

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(0u, packet, packet_len, K_NO_WAIT));

    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    second_tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    zassert_equal(read_be16(&second_tm_frame[4]) & 0x7ffu, TEST_TM_NO_FHP);
}

ZTEST(ccsds_tm_frame, test_tm_packet_admission_uses_configured_packet_max)
{
    uint8_t packet[CONFIG_AKIRA_CCSDS_TM_MAX_SPACE_PACKET_LEN + 1u];

    build_test_packet(packet, CONFIG_AKIRA_CCSDS_TM_MAX_SPACE_PACKET_LEN,
                      0x55u, 0xf0u);
    zassert_ok(ccsds_tm_frame_add(0u, packet,
                                  CONFIG_AKIRA_CCSDS_TM_MAX_SPACE_PACKET_LEN,
                                  K_NO_WAIT));

    build_test_packet(packet, sizeof(packet), 0x56u, 0xf1u);
    zassert_equal(ccsds_tm_frame_add(1u, packet, sizeof(packet), K_NO_WAIT),
                  -EMSGSIZE);
}

ZTEST(ccsds_tm_frame, test_active_output_counters_increment_predictably)
{
    static const uint8_t packet[] = {
        0x08, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xaa
    };
    struct tm_capture capture = {0};
    const uint8_t *first_frame;
    const uint8_t *second_frame;
    uint8_t first[TEST_TM_CODED_LEN];

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));

    zassert_ok(ccsds_tm_frame_add(0u, packet, sizeof(packet), K_NO_WAIT));
    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    memcpy(first, capture.frame, capture.len);

    zassert_ok(ccsds_tm_frame_add(0u, packet, sizeof(packet), K_NO_WAIT));
    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    first_frame = &first[TEST_TM_FRAME_OFFSET];
    second_frame = &capture.frame[TEST_TM_FRAME_OFFSET];

    zassert_equal(first_frame[2], 0u);
    zassert_equal(first_frame[3], 0u);
    zassert_equal(second_frame[2], 1u);
    zassert_equal(second_frame[3], 1u);
}

#ifdef CONFIG_AKIRA_CCSDS_RS
ZTEST(ccsds_tm_frame, test_active_output_includes_asm_and_rs_parity)
{
    static const uint8_t packet[] = {
        0x08, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xaa
    };
    struct tm_capture capture = {0};
    uint8_t expected_parity[CCSDS_RS_INTERLEAVED_PARITY_LEN];
    const uint8_t *tm_frame;
    const uint8_t *parity;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(0u, packet, sizeof(packet), K_NO_WAIT));

    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    parity = &capture.frame[TEST_TM_FRAME_OFFSET + TEST_TM_FRAME_LEN];
    ccsds_rs_encode(tm_frame, expected_parity);

    zassert_equal(capture.frame[0], TEST_TM_ASM0);
    zassert_equal(capture.frame[1], TEST_TM_ASM1);
    zassert_equal(capture.frame[2], TEST_TM_ASM2);
    zassert_equal(capture.frame[3], TEST_TM_ASM3);
    zassert_mem_equal(parity, expected_parity, sizeof(expected_parity));
}
#endif

#ifdef CONFIG_AKIRA_CCSDS_TM_FECF
ZTEST(ccsds_tm_frame, test_active_output_includes_fecf_before_rs_parity)
{
    static const uint8_t packet[] = {
        0x08, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xaa
    };
    struct tm_capture capture = {0};
    const uint8_t *tm_frame;
    size_t fecf_offset = TEST_TM_FRAME_LEN - TEST_TM_FECF_LEN;
    uint16_t expected_fecf;
    uint16_t actual_fecf;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(0u, packet, sizeof(packet), K_NO_WAIT));

    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    expected_fecf = ccsds_crc16_compute(tm_frame, fecf_offset);
    actual_fecf = read_be16(&tm_frame[fecf_offset]);

    zassert_equal(actual_fecf, expected_fecf);
    zassert_true(ccsds_crc16_check(tm_frame, TEST_TM_FRAME_LEN));
}
#endif

ZTEST(ccsds_tm_frame, test_idle_output_still_happens_after_packet_queue_drains)
{
    static const uint8_t packet[] = {
        0x08, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xaa
    };
    struct tm_capture capture = {0};
    const uint8_t *tm_frame;
    uint16_t word2;

    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE,
                                             capture_route, &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_set_vc_route(TEST_TM_IDLE_VC_ID,
                                           CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(0u, packet, sizeof(packet), K_NO_WAIT));

    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));

    tm_frame = &capture.frame[TEST_TM_FRAME_OFFSET];
    word2 = read_be16(&tm_frame[4]);

    zassert_equal(capture.vcid, TEST_TM_IDLE_VC_ID);
    zassert_equal(word2, TEST_TM_WORD2_IDLE);
}

ZTEST_SUITE(ccsds_tm_frame, NULL, NULL, tm_frame_setup, NULL, NULL);
