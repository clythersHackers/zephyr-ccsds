#include <zephyr/ztest.h>

#include <string.h>

#include "ccsds/ccsds_cfdp_checksum.h"

#define CCSDS_CFDP_STANDARD_VECTOR_CHECKSUM 0x181c2015u

struct memory_reader_context {
    const uint8_t *data;
    size_t len;
};

static enum ccsds_cfdp_status memory_read(void *user_data, uint32_t offset,
                                          uint8_t *buf, size_t cap,
                                          size_t *len)
{
    struct memory_reader_context *ctx =
        (struct memory_reader_context *)user_data;
    size_t remaining;
    size_t read_len;

    zassert_not_null(ctx);
    zassert_not_null(buf);
    zassert_not_null(len);

    if ((size_t)offset >= ctx->len || cap == 0u) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    remaining = ctx->len - (size_t)offset;
    read_len = remaining < cap ? remaining : cap;
    memcpy(buf, &ctx->data[offset], read_len);
    *len = read_len;

    return CCSDS_CFDP_STATUS_OK;
}

static uint32_t checksum_one_shot(const uint8_t *data, size_t len)
{
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);

    return checksum;
}

static uint32_t checksum_one_shot_type(enum ccsds_cfdp_checksum_type type,
                                       const uint8_t *data, size_t len)
{
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(&state, type),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);

    return checksum;
}

ZTEST(ccsds_cfdp_checksum, test_empty_modular_checksum_is_zero)
{
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum = 0xffffffffu;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, NULL, 0u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum, 0u);
}

ZTEST(ccsds_cfdp_checksum, test_standard_annex_f_vector)
{
    static const uint8_t data[] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
        0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu,
    };

    zassert_equal(checksum_one_shot(data, sizeof(data)),
                  CCSDS_CFDP_STANDARD_VECTOR_CHECKSUM);
}

ZTEST(ccsds_cfdp_checksum, test_single_buffer_checksum)
{
    static const uint8_t data[] = {
        0x12u, 0x34u, 0x56u, 0x78u, 0x9au, 0xbcu, 0xdeu, 0xf0u,
    };

    zassert_equal(checksum_one_shot(data, sizeof(data)), 0xacf13568u);
}

ZTEST(ccsds_cfdp_checksum, test_incremental_checksum_equals_one_shot)
{
    static const uint8_t data[] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
        0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu,
    };
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, 6u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 6u, &data[6], 6u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 12u, &data[12], 3u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(checksum, checksum_one_shot(data, sizeof(data)));
}

ZTEST(ccsds_cfdp_checksum, test_non_word_aligned_lengths)
{
    static const uint8_t one[] = { 0xaau };
    static const uint8_t three[] = { 0xaau, 0xbbu, 0xccu };
    static const uint8_t five[] = { 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu };

    zassert_equal(checksum_one_shot(one, sizeof(one)), 0xaa000000u);
    zassert_equal(checksum_one_shot(three, sizeof(three)), 0xaabbcc00u);
    zassert_equal(checksum_one_shot(five, sizeof(five)), 0x98bbccddu);
}

ZTEST(ccsds_cfdp_checksum, test_offset_sensitive_updates_match_annex_f)
{
    static const uint8_t segment0[] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
    };
    static const uint8_t segment6[] = {
        0x06u, 0x07u, 0x08u, 0x09u, 0x0au, 0x0bu,
    };
    static const uint8_t segment12[] = {
        0x0cu, 0x0du, 0x0eu,
    };
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, segment0,
                                             sizeof(segment0)),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 12u, segment12,
                                             sizeof(segment12)),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 6u, segment6,
                                             sizeof(segment6)),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(checksum, CCSDS_CFDP_STANDARD_VECTOR_CHECKSUM);
}

ZTEST(ccsds_cfdp_checksum, test_null_checksum_always_zero)
{
    static const uint8_t data[] = { 0xffu, 0xeeu, 0xddu, 0xccu };
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum = 0xffffffffu;

    zassert_equal(ccsds_cfdp_checksum_init(&state, CCSDS_CFDP_CHECKSUM_TYPE_NULL),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, sizeof(data)),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum, 0u);
}

ZTEST(ccsds_cfdp_checksum, test_finish_file_modular_does_not_require_reader)
{
    static const uint8_t data[] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
    };
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, sizeof(data)),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish_file(
                      &state, NULL, NULL, sizeof(data), NULL, 0u, &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum, checksum_one_shot(data, sizeof(data)));
}

ZTEST(ccsds_cfdp_checksum, test_crc32c_uses_standard_vector)
{
    static const uint8_t data[] = "123456789";

    zassert_equal(checksum_one_shot_type(CCSDS_CFDP_CHECKSUM_TYPE_CRC32C,
                                         data, sizeof(data) - 1u),
                  0xe3069283u);
}

ZTEST(ccsds_cfdp_checksum, test_ieee_802_3_fcs_uses_standard_vector)
{
    static const uint8_t data[] = "123456789";

    zassert_equal(checksum_one_shot_type(
                      CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS, data,
                      sizeof(data) - 1u),
                  0xcbf43926u);
}

ZTEST(ccsds_cfdp_checksum, test_crc_incremental_matches_one_shot)
{
    static const uint8_t data[] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u,
        0x07u, 0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu,
    };
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_CRC32C),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, 5u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 5u, &data[5],
                                             sizeof(data) - 5u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum,
                  checksum_one_shot_type(CCSDS_CFDP_CHECKSUM_TYPE_CRC32C,
                                         data, sizeof(data)));

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, 5u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 5u, &data[5],
                                             sizeof(data) - 5u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum,
                  checksum_one_shot_type(
                      CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS, data,
                      sizeof(data)));
}

ZTEST(ccsds_cfdp_checksum, test_crc_updates_defer_noncontiguous_offsets)
{
    static const uint8_t data[] = "123456789";
    struct memory_reader_context reader = {
        .data = data,
        .len = sizeof(data) - 1u,
    };
    ccsds_cfdp_checksum_state_t state;
    uint8_t scratch[4];
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_CRC32C),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 4u, &data[4], 5u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, 4u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_equal(ccsds_cfdp_checksum_finish_file(
                      &state, memory_read, &reader, sizeof(data) - 1u,
                      scratch, sizeof(scratch), &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum, 0xe3069283u);

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 4u, &data[4], 5u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, 4u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_equal(ccsds_cfdp_checksum_finish_file(
                      &state, memory_read, &reader, sizeof(data) - 1u,
                      scratch, sizeof(scratch), &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum, 0xcbf43926u);
}

ZTEST(ccsds_cfdp_checksum, test_finish_file_recomputes_incomplete_crc_stream)
{
    static const uint8_t data[] = "123456789";
    struct memory_reader_context reader = {
        .data = data,
        .len = sizeof(data) - 1u,
    };
    ccsds_cfdp_checksum_state_t state;
    uint8_t scratch[3];
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_CRC32C),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, 4u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish_file(
                      &state, memory_read, &reader, sizeof(data) - 1u,
                      scratch, sizeof(scratch), &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum, 0xe3069283u);
}

ZTEST(ccsds_cfdp_checksum, test_reports_out_of_order_update_capability)
{
    zassert_true(ccsds_cfdp_checksum_supports_out_of_order(
        CCSDS_CFDP_CHECKSUM_TYPE_MODULAR));
    zassert_true(ccsds_cfdp_checksum_supports_out_of_order(
        CCSDS_CFDP_CHECKSUM_TYPE_NULL));
    zassert_false(ccsds_cfdp_checksum_supports_out_of_order(
        CCSDS_CFDP_CHECKSUM_TYPE_CRC32C));
    zassert_false(ccsds_cfdp_checksum_supports_out_of_order(
        CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS));
    zassert_false(ccsds_cfdp_checksum_supports_out_of_order(
        (enum ccsds_cfdp_checksum_type)1));
}

ZTEST(ccsds_cfdp_checksum, test_unsupported_checksum_type_returns_status)
{
    ccsds_cfdp_checksum_state_t state;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, (enum ccsds_cfdp_checksum_type)1),
                  CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM);
}

ZTEST(ccsds_cfdp_checksum, test_zero_length_update_accepts_null_buffer)
{
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 123u, NULL, 0u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(checksum, 0u);
}

ZTEST_SUITE(ccsds_cfdp_checksum, NULL, NULL, NULL, NULL, NULL);
