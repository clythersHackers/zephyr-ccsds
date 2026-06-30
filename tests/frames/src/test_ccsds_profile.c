#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ccsds/ccsds_profile.h"

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
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
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
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
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
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
    profile.vc_state.lockout_flag = true;
    profile.vc_state.report_value = 0x10u;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EACCES);
    zassert_true(profile.vc_state.lockout_flag);
    zassert_equal(profile.vc_state.report_value, 0x10u);
}

ZTEST(ccsds_profile, test_tc_dispatch_advances_expected_fsn)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
    profile.vc_state.report_value = 0x1fu;
    profile.vc_state.retransmit_flag = true;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EMSGSIZE);
    zassert_equal(profile.vc_state.report_value, 0x20u);
    zassert_false(profile.vc_state.retransmit_flag);
}

ZTEST(ccsds_profile, test_tc_dispatch_rejects_data_frame_during_lockout)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
    profile.vc_state.lockout_flag = true;
    profile.vc_state.report_value = TEST_SHORT_DATA_FSN;

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EACCES);
    zassert_true(profile.vc_state.lockout_flag);
    zassert_equal(profile.vc_state.report_value, TEST_SHORT_DATA_FSN);
}

ZTEST(ccsds_profile, test_tc_dispatch_requests_retransmit_on_fsn_jump)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
    profile.vc_state.report_value = (uint8_t)(TEST_SHORT_DATA_FSN - 1u);

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EAGAIN);
    zassert_equal(profile.vc_state.report_value,
                  (uint8_t)(TEST_SHORT_DATA_FSN - 1u));
    zassert_true(profile.vc_state.retransmit_flag);
    zassert_false(profile.vc_state.lockout_flag);
}

ZTEST(ccsds_profile, test_tc_dispatch_discards_prior_fsn_without_retransmit)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
    profile.vc_state.report_value = (uint8_t)(TEST_SHORT_DATA_FSN + 1u);

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EAGAIN);
    zassert_equal(profile.vc_state.report_value,
                  (uint8_t)(TEST_SHORT_DATA_FSN + 1u));
    zassert_false(profile.vc_state.retransmit_flag);
    zassert_false(profile.vc_state.lockout_flag);
}

ZTEST(ccsds_profile, test_tc_dispatch_locks_out_on_fsn_window_boundary)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len = 0u;

    zassert_ok(decode_hex_fixture(short_data_cltu_hex, cltu, sizeof(cltu),
                                  &cltu_len));
    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
    profile.vc_state.report_value =
        (uint8_t)(TEST_SHORT_DATA_FSN - TEST_COP1_HALF_WINDOW);

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EAGAIN);
    zassert_equal(profile.vc_state.report_value,
                  (uint8_t)(TEST_SHORT_DATA_FSN - TEST_COP1_HALF_WINDOW));
    zassert_false(profile.vc_state.retransmit_flag);
    zassert_true(profile.vc_state.lockout_flag);
}

ZTEST(ccsds_profile, test_tc_build_clcw_packs_report_fields)
{
    struct ccsds_router router;
    struct ccsds_profile_tc_rx profile;
    uint32_t clcw;

    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));
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

    zassert_ok(ccsds_router_init(&router));
    zassert_ok(ccsds_profile_tc_rx_init(&profile, &router));

    zassert_equal(ccsds_profile_tc_set_accepted_vcid(&profile,
                                                     CCSDS_TC_VC_COUNT),
                  -EINVAL);
}

ZTEST_SUITE(ccsds_profile, NULL, NULL, profile_setup, NULL, NULL);
