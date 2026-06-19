#include <string.h>
#include <zephyr/ztest.h>

#include "ccsds/ccsds_bch.h"

ZTEST(ccsds_bch, test_zero_data_vector)
{
    /* All-zero data has zero BCH remainder; CCSDS transmits parity inverted. */
    uint8_t block[CCSDS_BCH_BLOCK_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe
    };
    int corrected_bit = 123;

    zassert_equal(ccsds_bch_decode_block(block, &corrected_bit),
                  CCSDS_BCH_OK);
    zassert_equal(corrected_bit, -1);
}

ZTEST(ccsds_bch, test_nonzero_data_vector)
{
    /* 0x0123456789abcd encoded with g(x)=x^7+x^6+x^2+1, parity inverted. */
    uint8_t block[CCSDS_BCH_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90
    };
    int corrected_bit = 123;

    zassert_equal(ccsds_bch_decode_block(block, &corrected_bit),
                  CCSDS_BCH_OK);
    zassert_equal(corrected_bit, -1);
}

ZTEST(ccsds_bch, test_corrects_each_single_bit_error)
{
    static const uint8_t expected[CCSDS_BCH_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90
    };

    for (int bit = 0; bit < 63; bit++) {
        uint8_t block[CCSDS_BCH_BLOCK_SIZE];
        int corrected_bit = -1;

        memcpy(block, expected, sizeof(block));
        block[bit / 8] ^= (uint8_t)(0x80u >> (bit % 8));

        zassert_equal(ccsds_bch_decode_block(block, &corrected_bit),
                      CCSDS_BCH_CORRECTED, "bit %d", bit);
        zassert_equal(corrected_bit, bit, "bit %d", bit);
        zassert_mem_equal(block, expected, sizeof(block), "bit %d", bit);
    }
}

ZTEST(ccsds_bch, test_detects_double_bit_error)
{
    uint8_t block[CCSDS_BCH_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x90
    };
    int corrected_bit = 123;

    block[0] ^= 0x80u;
    block[7] ^= 0x02u;

    zassert_equal(ccsds_bch_decode_block(block, &corrected_bit),
                  CCSDS_BCH_DETECTED_EVEN);
    zassert_equal(corrected_bit, -1);
}

ZTEST_SUITE(ccsds_bch, NULL, NULL, NULL, NULL, NULL);
