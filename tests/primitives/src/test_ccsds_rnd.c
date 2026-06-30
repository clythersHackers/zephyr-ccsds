#include <string.h>

#include <zephyr/ztest.h>

#include "ccsds/ccsds_rnd.h"

ZTEST(ccsds_rnd, test_known_sequence_prefix)
{
    static const uint8_t expected[] = {
        0xff, 0x48, 0x0e, 0xc0, 0x9a, 0x0d, 0x70, 0xbc,
        0x8e, 0x2c, 0x93, 0xad, 0xa7, 0xb7, 0x46, 0xce,
        0x5a, 0x97, 0x7d, 0xcc, 0x32, 0xa2, 0xbf, 0x3e,
        0x0a, 0x10, 0xf1, 0x88, 0x94, 0xcd, 0xea, 0xb1,
        0xfe, 0x90, 0x1d, 0x81, 0x34, 0x1a, 0xe1, 0x79,
    };
    uint8_t data[sizeof(expected)] = { 0 };

    ccsds_rnd_apply(data, sizeof(data));
    zassert_mem_equal(data, expected, sizeof(expected));
}

ZTEST(ccsds_rnd, test_apply_is_self_inverse)
{
    uint8_t data[] = {
        0x08, 0x2a, 0xc0, 0x01, 0x00, 0x03, 0xde, 0xad,
        0xbe, 0xef, 0x55, 0xaa, 0x12, 0x34, 0x56, 0x78,
    };
    uint8_t original[sizeof(data)];

    memcpy(original, data, sizeof(data));

    ccsds_rnd_apply(data, sizeof(data));
    zassert_not_equal(memcmp(data, original, sizeof(data)), 0);
    ccsds_rnd_apply(data, sizeof(data));
    zassert_mem_equal(data, original, sizeof(data));
}

ZTEST(ccsds_rnd, test_wraps_after_255_bytes)
{
    uint8_t data[256] = { 0 };

    ccsds_rnd_apply(data, sizeof(data));
    zassert_equal(data[0], data[255]);
}

ZTEST(ccsds_rnd, test_accepts_null_empty_buffer)
{
    ccsds_rnd_apply(NULL, 0u);
}

ZTEST_SUITE(ccsds_rnd, NULL, NULL, NULL, NULL, NULL);
