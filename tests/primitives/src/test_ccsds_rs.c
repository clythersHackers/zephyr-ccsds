#include <string.h>
#include <zephyr/ztest.h>

#include "ccsds/ccsds_rs.h"

static const uint8_t rs_generator[CCSDS_RS_PARITY_LEN] = {
    0x01, 0x18, 0x14, 0x1d, 0x24, 0x11, 0x1a, 0x0c,
    0x1e, 0x22, 0x07, 0x0c, 0x25, 0xfe, 0x61, 0x26,
    0xef, 0x2c, 0x3d, 0x2a, 0x2c, 0xec, 0xda, 0xeb,
    0xc1, 0x6e, 0xda, 0x20, 0x28, 0x2c, 0xc1, 0xa8
};

static uint8_t rs_ref_gf_mul(uint8_t a, uint8_t b)
{
    uint8_t product = 0u;

    while (a != 0u && b != 0u) {
        if ((b & 1u) != 0u) {
            product ^= a;
        }

        a = (a & 0x80u) != 0u ? (uint8_t)((a << 1) ^ 0x87u) :
                                 (uint8_t)(a << 1);
        b >>= 1;
    }

    return product;
}

static void rs_ref_encode_codeblock(const uint8_t *data, uint8_t *parity)
{
    memset(parity, 0, CCSDS_RS_PARITY_LEN);

    for (size_t i = 0u; i < CCSDS_RS_DATA_LEN; i++) {
        uint8_t feedback = data[i] ^ parity[CCSDS_RS_PARITY_LEN - 1u];

        for (size_t j = CCSDS_RS_PARITY_LEN - 1u; j > 0u; j--) {
            parity[j] = parity[j - 1u] ^
                        rs_ref_gf_mul(feedback, rs_generator[j]);
        }

        parity[0] = feedback;
    }
}

static void assert_encoded_matches_reference(
    const uint8_t data[CCSDS_RS_INTERLEAVED_DATA_LEN])
{
    uint8_t expected_parity[CCSDS_RS_INTERLEAVED_PARITY_LEN];
    uint8_t parity[CCSDS_RS_INTERLEAVED_PARITY_LEN];

    for (size_t i = 0u; i < CCSDS_RS_INTERLEAVE_DEPTH; i++) {
        rs_ref_encode_codeblock(data + (i * CCSDS_RS_DATA_LEN),
                                expected_parity +
                                    (i * CCSDS_RS_PARITY_LEN));
    }

    memset(parity, 0xa5, sizeof(parity));

    ccsds_rs_encode(data, parity);

    zassert_mem_equal(parity, expected_parity, CCSDS_RS_INTERLEAVED_PARITY_LEN);
}

ZTEST(ccsds_rs, test_zero_data_vector)
{
    uint8_t data[CCSDS_RS_INTERLEAVED_DATA_LEN] = {0};

    assert_encoded_matches_reference(data);
}

ZTEST(ccsds_rs, test_pattern_data_vector)
{
    uint8_t data[CCSDS_RS_INTERLEAVED_DATA_LEN];

    for (size_t i = 0u; i < sizeof(data); i++) {
        data[i] = (uint8_t)((i * 37u) ^ (i >> 1) ^ 0x5au);
    }

    assert_encoded_matches_reference(data);
}

ZTEST_SUITE(ccsds_rs, NULL, NULL, NULL, NULL, NULL);
