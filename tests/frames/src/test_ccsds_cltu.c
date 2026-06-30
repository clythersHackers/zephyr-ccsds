#include <zephyr/ztest.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "ccsds/ccsds_cltu.h"

struct cltu_hex_fixture {
    const char *name;
    const char *hex;
    size_t decoded_len;
};

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

ZTEST(ccsds_cltu, test_decode_rejects_bad_start_sequence)
{
    static const uint8_t cltu[] = {
        0x00, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0x79,
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
        0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0x79,
    };
    uint8_t frame[CCSDS_BCH_DATA_SIZE];
    size_t frame_len = 123;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  -EINVAL);
    zassert_equal(frame_len, 0);
}

ZTEST(ccsds_cltu, test_decode_rejects_bad_tail_end_byte)
{
    static const uint8_t cltu[] = {
        0xeb, 0x90,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0x78,
    };
    uint8_t frame[CCSDS_BCH_DATA_SIZE];
    size_t frame_len = 123;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  -EINVAL);
    zassert_equal(frame_len, 0);
}

ZTEST(ccsds_cltu, test_decode_rejects_bad_tail_sequence_byte)
{
    static const uint8_t cltu[] = {
        0xeb, 0x90,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90,
        0xc5, 0xc5, 0xc5, 0x00, 0xc5, 0xc5, 0xc5, 0x79,
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
        0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0x79,
    };
    uint8_t frame[CCSDS_BCH_DATA_SIZE - 1u];
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
        0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0x79,
    };
    static const uint8_t expected[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
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
        0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0x79,
    };
    static const uint8_t expected[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
    };
    uint8_t frame[sizeof(expected)];
    size_t frame_len = 0;

    zassert_equal(ccsds_cltu_decode_message(cltu, sizeof(cltu), frame,
                                            sizeof(frame), &frame_len),
                  0);
    zassert_equal(frame_len, sizeof(expected));
    zassert_mem_equal(frame, expected, sizeof(expected));
}

ZTEST(ccsds_cltu, test_decode_accepts_recorded_valid_cltus)
{
    static const struct cltu_hex_fixture fixtures[] = {
        {
            .name = "BC unlock control frame",
            .hex = "eb90307b0007000055f07555555555555522c5c5c5c5c5c5c579",
            .decoded_len = 14u,
        },
        {
            .name = "SET VR control frame",
            .hex = "eb90307b00090082002a1fa63455555555a2c5c5c5c5c5c5c579",
            .decoded_len = 14u,
        },
        {
            .name = "short TC",
            .hex = "eb90007b00191fc0186410c006000b100e16020000010319008800bbe915465555d2c5c5c5c5c5c5c579",
            .decoded_len = 28u,
        },
        {
            .name = "long TC",
            .hex = "eb90007b00ff20c0188810c00700f11002b201000075040004da010402040204031004040405040604fc0704080409040a6a040b040c040d049e0e040f04100411b404120413041404be15041604170418fc0419041a041b04a41c041d041e041f6604200421042204de230424042504265804270428042904d42a042b042c042d2e042e042f043004fc310432043304343204350436043704b8380439043a043b4e043c043d043e04463f044004410442d604430444044504da46044704480449be044a044b044c04864d044e044f0450a404510452045304e0540455045604573604580459045a041e5b045c045d045eda045f04600461046a620463046404657e046604670468040269046a046b046c2c046d046e046f0480700471047204731e347279775555557cc5c5c5c5c5c5c579",
            .decoded_len = 259u,
        },
    };
    uint8_t cltu[CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN];
    uint8_t frame[CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN];

    for (size_t i = 0u; i < ARRAY_SIZE(fixtures); i++) {
        size_t cltu_len = 0u;
        size_t frame_len = 0u;

        zassert_ok(decode_hex_fixture(fixtures[i].hex, cltu, sizeof(cltu),
                                      &cltu_len),
                   "%s", fixtures[i].name);
        zassert_ok(ccsds_cltu_decode_message(cltu, cltu_len, frame,
                                             sizeof(frame), &frame_len),
                   "%s", fixtures[i].name);
        zassert_equal(frame_len, fixtures[i].decoded_len, "%s",
                      fixtures[i].name);
    }
}

ZTEST_SUITE(ccsds_cltu, NULL, NULL, NULL, NULL, NULL);
