#include <string.h>

#include <psa/crypto.h>
#include <zephyr/ztest.h>

static void wipe_key(uint8_t *key, size_t len)
{
    volatile uint8_t *p = key;

    while (len-- > 0u) {
        *p++ = 0u;
    }
}

static psa_key_id_t imported_key = PSA_KEY_ID_NULL;

static psa_key_id_t import_test_key(uint8_t plaintext_key[32])
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t status;

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256u);
    status = psa_import_key(&attributes, plaintext_key, 32u, &key_id);
    wipe_key(plaintext_key, 32u);
    psa_reset_key_attributes(&attributes);

    zassert_mem_equal(plaintext_key, (uint8_t[32]){ 0 },
                      32u);
    zassert_equal(status, PSA_SUCCESS);
    imported_key = key_id;
    return key_id;
}

ZTEST(sdls_psa, test_nist_aes_256_gcm_encrypt_decrypt_and_bad_tag)
{
    /* NIST SP 800-38D AES-256-GCM, zero key/IV, one zero block. */
    uint8_t key_bytes[32] = { 0 };
    static const uint8_t nonce[12] = { 0 };
    static const uint8_t plaintext[16] = { 0 };
    static const uint8_t expected[32] = {
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    };
    psa_key_id_t key_id = import_test_key(key_bytes);
    uint8_t encrypted[sizeof(expected)];
    uint8_t decrypted[sizeof(plaintext)];
    size_t output_len;

    zassert_equal(psa_aead_encrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                   NULL, 0u, plaintext, sizeof(plaintext),
                                   encrypted, sizeof(encrypted), &output_len),
                  PSA_SUCCESS);
    zassert_equal(output_len, sizeof(expected));
    zassert_mem_equal(encrypted, expected, sizeof(expected));
    zassert_equal(psa_aead_decrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                   NULL, 0u, encrypted, output_len, decrypted,
                                   sizeof(decrypted), &output_len),
                  PSA_SUCCESS);
    zassert_equal(output_len, sizeof(plaintext));
    zassert_mem_equal(decrypted, plaintext, sizeof(plaintext));

    encrypted[sizeof(encrypted) - 1u] ^= 0x01u;
    zassert_equal(psa_aead_decrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                   NULL, 0u, encrypted, sizeof(encrypted),
                                   decrypted, sizeof(decrypted), &output_len),
                  PSA_ERROR_INVALID_SIGNATURE);
}

ZTEST(sdls_psa, test_nist_gmac_style_zero_plaintext_with_aad)
{
    /*
     * NIST GCMVS AES-256 Count 0 (128-bit tag, zero plaintext, 1024-bit AAD).
     * This is GMAC: the entire input is AAD and PSA receives no plaintext.
     */
    uint8_t key_bytes[32] = {
        0x43, 0xc9, 0xe2, 0x09, 0xda, 0x3c, 0x19, 0x71,
        0xd9, 0x86, 0xa4, 0x5b, 0x92, 0xf2, 0xfa, 0x0d,
        0x2d, 0x15, 0x51, 0x83, 0x73, 0x0d, 0x21, 0xd7,
        0x1e, 0xd8, 0xe2, 0x28, 0x4e, 0xc3, 0x08, 0xe3,
    };
    static const uint8_t nonce[16] = {
        0x78, 0xbe, 0xf6, 0x55, 0xdf, 0xd8, 0x99, 0x0b,
        0x04, 0xd2, 0xa2, 0x56, 0x78, 0xd7, 0x08, 0x6d,
    };
    static const uint8_t aad[128] = {
        0x9d, 0x8c, 0x67, 0x34, 0x54, 0x67, 0x97, 0xc5,
        0x81, 0xb9, 0xb1, 0xd0, 0xd4, 0xf0, 0x5b, 0x27,
        0xfe, 0x05, 0x39, 0xbd, 0x01, 0x65, 0x5d, 0x2d,
        0x1a, 0x8a, 0x14, 0x89, 0xcd, 0xf8, 0x04, 0x22,
        0x87, 0x53, 0xd7, 0x72, 0x72, 0xbf, 0x6d, 0xed,
        0x19, 0xd4, 0x7a, 0x6a, 0xbd, 0x62, 0x81, 0xea,
        0x95, 0x91, 0xd4, 0xbc, 0xc1, 0xbe, 0x22, 0x23,
        0x05, 0xfd, 0xf6, 0x89, 0xc5, 0xfa, 0xa4, 0xc1,
        0x13, 0x31, 0xcf, 0xfb, 0xf4, 0x22, 0x15, 0x46,
        0x9b, 0x81, 0xf6, 0x1b, 0x40, 0x41, 0x5d, 0x81,
        0xcc, 0x37, 0x16, 0x1e, 0x5c, 0x02, 0x58, 0xa6,
        0x76, 0x42, 0xb9, 0xb8, 0xac, 0x62, 0x7d, 0x6e,
        0x39, 0xf4, 0x3e, 0x48, 0x5e, 0x1f, 0xf5, 0x22,
        0xac, 0x74, 0x2a, 0x07, 0xde, 0xfa, 0x35, 0x69,
        0xae, 0xb5, 0x99, 0x90, 0xcb, 0x44, 0xc4, 0xf3,
        0xd9, 0x52, 0xf8, 0x11, 0x9f, 0xf1, 0x11, 0x1d,
    };
    static const uint8_t expected_tag[16] = {
        0xf1, 0x5d, 0xdf, 0x93, 0x8b, 0xbf, 0x52, 0xc2,
        0x97, 0x7a, 0xda, 0xba, 0xf4, 0x12, 0x0d, 0xe8,
    };
    psa_key_id_t key_id = import_test_key(key_bytes);
    uint8_t tag[16];
    uint8_t no_plaintext[1];
    size_t output_len;

    zassert_equal(psa_aead_encrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                   aad, sizeof(aad), NULL, 0u, tag,
                                   sizeof(tag), &output_len),
                  PSA_SUCCESS);
    zassert_equal(output_len, sizeof(tag));
    zassert_mem_equal(tag, expected_tag, sizeof(expected_tag));
    zassert_equal(psa_aead_decrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                   aad, sizeof(aad), tag, sizeof(tag),
                                   no_plaintext, sizeof(no_plaintext),
                                   &output_len),
                  PSA_SUCCESS);
    zassert_equal(output_len, 0u);

    tag[0] ^= 0x80u;
    zassert_equal(psa_aead_decrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                   aad, sizeof(aad), tag, sizeof(tag),
                                   no_plaintext, sizeof(no_plaintext),
                                   &output_len),
                  PSA_ERROR_INVALID_SIGNATURE);
}

static void *sdls_psa_setup(void)
{
    zassert_equal(psa_crypto_init(), PSA_SUCCESS);
    return NULL;
}

static void sdls_psa_after(void *fixture)
{
    ARG_UNUSED(fixture);

    if (imported_key != PSA_KEY_ID_NULL) {
        zassert_equal(psa_destroy_key(imported_key), PSA_SUCCESS);
        imported_key = PSA_KEY_ID_NULL;
    }
}

ZTEST_SUITE(sdls_psa, NULL, sdls_psa_setup, NULL, sdls_psa_after, NULL);
