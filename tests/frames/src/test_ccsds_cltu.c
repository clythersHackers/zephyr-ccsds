#include <zephyr/ztest.h>
#include <errno.h>

#include "ccsds/ccsds_cltu.h"

ZTEST(ccsds_cltu, test_start_sequence_accepts_exact_match)
{
    static const uint8_t candidate[] = {0xeb, 0x90};

    zassert_true(ccsds_cltu_is_start_sequence(candidate));
}

ZTEST(ccsds_cltu, test_start_sequence_accepts_one_bit_error)
{
    for (int bit = 0; bit < 16; bit++) {
        uint16_t value = CLTU_START_SEQUENCE ^ (uint16_t)(1u << bit);
        uint8_t candidate[] = {
            (uint8_t)(value >> 8),
            (uint8_t)value,
        };

        zassert_true(ccsds_cltu_is_start_sequence(candidate), "bit %d", bit);
    }
}

ZTEST(ccsds_cltu, test_start_sequence_rejects_two_bit_error)
{
    uint16_t value = CLTU_START_SEQUENCE ^ 0x0003u;
    uint8_t candidate[] = {
        (uint8_t)(value >> 8),
        (uint8_t)value,
    };

    zassert_false(ccsds_cltu_is_start_sequence(candidate));
}

ZTEST(ccsds_cltu, test_start_sequence_rejects_null)
{
    zassert_false(ccsds_cltu_is_start_sequence(NULL));
}

ZTEST(ccsds_cltu, test_decode_rejects_bad_start_sequence)
{
    static const uint8_t cltu[] = {
        0x00, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe,
    };
    uint8_t frame[1];
    size_t frame_len = 0;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  -EINVAL);
}

ZTEST(ccsds_cltu, test_decode_rejects_short_cltu)
{
    static const uint8_t cltu[] = {0xeb, 0x90};
    uint8_t frame[1];
    size_t frame_len = 0;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  -EINVAL);
}

ZTEST(ccsds_cltu, test_decode_rejects_unaligned_bch_body)
{
    static const uint8_t cltu[] = {
        0xeb, 0x90,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0x00,
    };
    uint8_t frame[CCSDS_BCH_DATA_SIZE];
    size_t frame_len = 123;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  -EINVAL);
    zassert_equal(frame_len, 0);
}

ZTEST(ccsds_cltu, test_decode_rejects_small_output_buffer)
{
    static const uint8_t cltu[] = {
        0xeb, 0x90,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe,
    };
    uint8_t frame[(2u * CCSDS_BCH_DATA_SIZE) - 1u];
    size_t frame_len = 123;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  -ENOSPC);
    zassert_equal(frame_len, 0);
}

ZTEST(ccsds_cltu, test_decode_copies_bch_data_to_tc_frame)
{
    static const uint8_t cltu[] = {
        0xeb, 0x90,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe,
    };
    static const uint8_t expected[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t frame[sizeof(expected)];
    size_t frame_len = 0;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  0);
    zassert_equal(frame_len, sizeof(expected));
    zassert_mem_equal(frame, expected, sizeof(expected));
}

ZTEST(ccsds_cltu, test_decode_corrects_single_bit_before_copy)
{
    uint8_t cltu[] = {
        0xeb, 0x90,
        0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe,
    };
    static const uint8_t expected[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t frame[sizeof(expected)];
    size_t frame_len = 0;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  0);
    zassert_equal(frame_len, sizeof(expected));
    zassert_mem_equal(frame, expected, sizeof(expected));
}

ZTEST_SUITE(ccsds_cltu, NULL, NULL, NULL, NULL, NULL);
