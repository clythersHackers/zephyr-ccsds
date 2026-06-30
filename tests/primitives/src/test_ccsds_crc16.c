#include <zephyr/ztest.h>

#include "ccsds/ccsds_crc16.h"

ZTEST(ccsds_crc16, test_standard_check_vector)
{
    static const uint8_t data[] = "123456789";

    zassert_equal(ccsds_crc16_compute(data, sizeof(data) - 1u),
                  CCSDS_CRC16_CHECK_VECTOR);
}

ZTEST(ccsds_crc16, test_incremental_matches_one_shot)
{
    static const uint8_t data[] = {
        0x08, 0x2a, 0xc0, 0x01, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef
    };
    uint16_t crc = CCSDS_CRC16_INIT;

    crc = ccsds_crc16_update(crc, data, 3u);
    crc = ccsds_crc16_update(crc, data + 3u, sizeof(data) - 3u);

    zassert_equal(crc, ccsds_crc16_compute(data, sizeof(data)));
}

ZTEST(ccsds_crc16, test_check_accepts_valid_codeword)
{
    uint8_t codeword[] = {
        0x08, 0x2a, 0xc0, 0x01, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef,
        0x00, 0x00
    };
    uint16_t crc = ccsds_crc16_compute(codeword,
                                       sizeof(codeword) - CCSDS_CRC16_LEN);

    codeword[sizeof(codeword) - 2u] = (uint8_t)(crc >> 8);
    codeword[sizeof(codeword) - 1u] = (uint8_t)crc;

    zassert_true(ccsds_crc16_check(codeword, sizeof(codeword)));
    zassert_equal(ccsds_crc16_compute(codeword, sizeof(codeword)), 0u);
}

ZTEST(ccsds_crc16, test_check_rejects_invalid_codeword)
{
    uint8_t codeword[] = {
        0x08, 0x2a, 0xc0, 0x01, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef,
        0x00, 0x00
    };
    uint16_t crc = ccsds_crc16_compute(codeword,
                                       sizeof(codeword) - CCSDS_CRC16_LEN);

    codeword[sizeof(codeword) - 2u] = (uint8_t)(crc >> 8);
    codeword[sizeof(codeword) - 1u] = (uint8_t)crc;
    codeword[4] ^= 0x01u;

    zassert_false(ccsds_crc16_check(codeword, sizeof(codeword)));
}

ZTEST(ccsds_crc16, test_check_rejects_missing_crc)
{
    static const uint8_t data[] = { 0x00 };

    zassert_false(ccsds_crc16_check(data, sizeof(data)));
}

ZTEST_SUITE(ccsds_crc16, NULL, NULL, NULL, NULL, NULL);
