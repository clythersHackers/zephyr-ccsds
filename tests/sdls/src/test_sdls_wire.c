#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <ccsds/ccsds_sdls.h>

#define TEST_SPI 1u
#define TEST_KEY_ID CONFIG_CCSDS_SDLS_SESSION_KEY_BASE

static psa_key_id_t test_psa_key;

static void init_ctx(struct ccsds_sdls_ctx *ctx, enum ccsds_sdls_sa_role role,
                     enum ccsds_sdls_security_mode mode,
                     enum ccsds_sdls_sa_state sa_state,
                     enum ccsds_sdls_key_state key_state)
{
    struct ccsds_sdls_key_init key = {
        .psa_key_id = test_psa_key,
        .key_id = TEST_KEY_ID,
        .state = key_state,
    };
    struct ccsds_sdls_sa_init sa = {
        .spi = TEST_SPI,
        .key_id = TEST_KEY_ID,
        .role = role,
        .mode = mode,
        .state = sa_state,
        .has_key = true,
    };

    ccsds_sdls_init(ctx, &sa, 1u, &key, 1u);
}

static void import_key(void)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, CCSDS_SDLS_AES_KEY_BITS);
    zassert_equal(psa_import_key(&attributes, key, sizeof(key), &test_psa_key),
                  PSA_SUCCESS);
    memset(key, 0, sizeof(key));
    psa_reset_key_attributes(&attributes);
}

static int protect(struct ccsds_sdls_ctx *ctx, enum ccsds_sdls_sa_role role,
                   struct ccsds_sdls_auth_header auth, const uint8_t *clear,
                   size_t clear_len, uint8_t *protected_data)
{
    uint8_t scratch[160];
    struct ccsds_sdls_workspace workspace = {
        .data = scratch,
        .capacity = sizeof(scratch),
    };

    return ccsds_sdls_apply_security(ctx, role, TEST_SPI, auth, clear,
                                     clear_len, workspace, protected_data,
                                     clear_len + CCSDS_SDLS_PROTECTED_OVERHEAD);
}

static int process(struct ccsds_sdls_ctx *ctx, enum ccsds_sdls_sa_role role,
                   struct ccsds_sdls_auth_header auth,
                   const uint8_t *protected_data, size_t protected_len,
                   uint8_t *clear)
{
    uint8_t scratch[160];
    struct ccsds_sdls_workspace workspace = {
        .data = scratch,
        .capacity = sizeof(scratch),
    };

    return ccsds_sdls_process_security(
        ctx, role, auth, protected_data, protected_len, workspace, clear,
        protected_len - CCSDS_SDLS_PROTECTED_OVERHEAD);
}

ZTEST(sdls_wire, test_header_and_trailer_exact_wire_bytes)
{
    struct ccsds_sdls_security_header decoded_header;
    struct ccsds_sdls_security_header header = {
        .spi = 0x1234u,
        .iv = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
               0xbb},
    };
    struct ccsds_sdls_security_trailer decoded_trailer;
    struct ccsds_sdls_security_trailer trailer;
    uint8_t encoded_header[CCSDS_SDLS_SECURITY_HEADER_LEN];
    uint8_t encoded_trailer[CCSDS_SDLS_SECURITY_TRAILER_LEN];
    static const uint8_t expected_header[CCSDS_SDLS_SECURITY_HEADER_LEN] = {
        0x12, 0x34, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    };
    static const uint8_t expected_tm_mask[] = {0x3f, 0xfe, 0x00,
                                               0x00, 0x00, 0x00};
    static const uint8_t expected_tc_mask[] = {0x03, 0xff, 0xfc, 0x00, 0x00};

    BUILD_ASSERT(sizeof(ccsds_sdls_tm_default_auth_mask) ==
                 CCSDS_SDLS_TM_DEFAULT_AUTH_MASK_LEN);
    BUILD_ASSERT(sizeof(ccsds_sdls_tc_default_auth_mask) ==
                 CCSDS_SDLS_TC_DEFAULT_AUTH_MASK_LEN);
    zassert_mem_equal(ccsds_sdls_tm_default_auth_mask, expected_tm_mask,
                      sizeof(expected_tm_mask));
    zassert_mem_equal(ccsds_sdls_tc_default_auth_mask, expected_tc_mask,
                      sizeof(expected_tc_mask));

    for (size_t i = 0u; i < sizeof(trailer.tag); i++) {
        trailer.tag[i] = (uint8_t)(0xa0u + i);
    }

    ccsds_sdls_security_header_encode(&header, encoded_header);
    zassert_mem_equal(encoded_header, expected_header, sizeof(expected_header));
    zassert_ok(ccsds_sdls_security_header_decode(
        encoded_header, sizeof(encoded_header), &decoded_header));
    zassert_equal(decoded_header.spi, header.spi);
    zassert_mem_equal(decoded_header.iv, header.iv, sizeof(header.iv));

    ccsds_sdls_security_trailer_encode(&trailer, encoded_trailer);
    zassert_mem_equal(encoded_trailer, trailer.tag, sizeof(trailer.tag));
    zassert_ok(ccsds_sdls_security_trailer_decode(
        encoded_trailer, sizeof(encoded_trailer), &decoded_trailer));
    zassert_mem_equal(decoded_trailer.tag, trailer.tag, sizeof(trailer.tag));
}

ZTEST(sdls_wire, test_received_codec_lengths_and_reserved_spi)
{
    struct ccsds_sdls_security_header header;
    struct ccsds_sdls_security_trailer trailer;
    uint8_t bytes[CCSDS_SDLS_SECURITY_HEADER_LEN + 1u] = {0};

    zassert_equal(ccsds_sdls_security_header_decode(
                      bytes, CCSDS_SDLS_SECURITY_HEADER_LEN - 1u, &header),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_security_header_decode(
                      bytes, CCSDS_SDLS_SECURITY_HEADER_LEN + 1u, &header),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_security_trailer_decode(
                      bytes, CCSDS_SDLS_SECURITY_TRAILER_LEN + 1u, &trailer),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_security_header_decode(
                      bytes, CCSDS_SDLS_SECURITY_HEADER_LEN, &header),
                  CCSDS_SDLS_ERR_FORMAT);
    bytes[0] = 0xffu;
    bytes[1] = 0xffu;
    zassert_equal(ccsds_sdls_security_header_decode(
                      bytes, CCSDS_SDLS_SECURITY_HEADER_LEN, &header),
                  CCSDS_SDLS_ERR_FORMAT);
}

ZTEST(sdls_wire, test_iv_fields_are_independent)
{
    static const struct {
        uint64_t sender_iv;
        uint32_t arsn;
        uint8_t iv[CCSDS_SDLS_IV_LEN];
    } vectors[] = {
        {0u, 0u, {0}},
        {UINT64_C(0x0123456789abcdef),
         1u,
         {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00,
          0x01}},
        {UINT64_MAX,
         UINT32_MAX,
         {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff}},
    };
    uint8_t iv[CCSDS_SDLS_IV_LEN];

    for (size_t i = 0u; i < ARRAY_SIZE(vectors); i++) {
        ccsds_sdls_construct_iv(vectors[i].sender_iv, vectors[i].arsn, iv);
        zassert_mem_equal(iv, vectors[i].iv, sizeof(iv));
        zassert_equal(sys_get_be64(iv), vectors[i].sender_iv);
        zassert_equal(ccsds_sdls_iv_arsn(iv), vectors[i].arsn);
    }
}

ZTEST(sdls_wire, test_gcm_round_trip_with_compact_mask)
{
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    uint8_t prefix[] = {0x12, 0x34, 0x56, 0x78};
    static const uint8_t mask[] = {0xff, 0x00};
    struct ccsds_sdls_auth_header auth = {
        .data = prefix,
        .mask = mask,
        .len = sizeof(prefix),
        .mask_len = sizeof(mask),
    };
    static const uint8_t clear[] = {1, 2, 3, 4, 5, 6};
    uint8_t protected_data[sizeof(clear) + CCSDS_SDLS_PROTECTED_OVERHEAD];
    uint8_t output[sizeof(clear)] = {0};

    init_ctx(&tx, CCSDS_SDLS_SA_OPERATIONAL_TM_TX, CCSDS_SDLS_MODE_GCM,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    init_ctx(&rx, CCSDS_SDLS_SA_EP_COMMAND_RX, CCSDS_SDLS_MODE_GCM,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    tx.tx_iv = UINT64_C(0x0123456789abcdef);
    zassert_ok(protect(&tx, CCSDS_SDLS_SA_OPERATIONAL_TM_TX, auth, clear,
                       sizeof(clear), protected_data));

    prefix[1] ^= 0xffu;
    zassert_ok(process(&rx, CCSDS_SDLS_SA_EP_COMMAND_RX, auth, protected_data,
                       sizeof(protected_data), output));
    zassert_mem_equal(output, clear, sizeof(clear));

    init_ctx(&rx, CCSDS_SDLS_SA_EP_COMMAND_RX, CCSDS_SDLS_MODE_GCM,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    prefix[2] ^= 1u; /* Beyond mask_len: implicitly authenticated. */
    memset(output, 0xa5, sizeof(output));
    zassert_equal(process(&rx, CCSDS_SDLS_SA_EP_COMMAND_RX, auth,
                          protected_data, sizeof(protected_data), output),
                  CCSDS_SDLS_ERR_AUTHENTICATION);
    zassert_mem_equal(
        output, (uint8_t[sizeof(output)]){[0 ... sizeof(output) - 1] = 0xa5},
        sizeof(output));
    zassert_false(rx.sas[0].rx_arsn_initialized);
}

ZTEST(sdls_wire, test_gmac_round_trip_and_tamper)
{
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    static const uint8_t prefix[] = {0x20, 0x01, 0x02};
    static const uint8_t mask[] = {0xff, 0x00};
    struct ccsds_sdls_auth_header auth = {
        .data = prefix,
        .mask = mask,
        .len = sizeof(prefix),
        .mask_len = sizeof(mask),
    };
    static const uint8_t clear[] = {0xaa, 0xbb, 0xcc};
    uint8_t protected_data[sizeof(clear) + CCSDS_SDLS_PROTECTED_OVERHEAD];
    uint8_t output[sizeof(clear)] = {0};

    init_ctx(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    init_ctx(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    zassert_ok(protect(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, auth, clear,
                       sizeof(clear), protected_data));
    zassert_mem_equal(protected_data + CCSDS_SDLS_SECURITY_HEADER_LEN, clear,
                      sizeof(clear));
    zassert_ok(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, auth,
                       protected_data, sizeof(protected_data), output));
    zassert_mem_equal(output, clear, sizeof(clear));

    init_ctx(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    protected_data[sizeof(protected_data) - 1u] ^= 1u;
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, auth,
                          protected_data, sizeof(protected_data), output),
                  CCSDS_SDLS_ERR_AUTHENTICATION);
    zassert_false(rx.sas[0].rx_arsn_initialized);
}

ZTEST(sdls_wire, test_monotonic_replay_window_allows_only_forward_gaps)
{
    struct ccsds_sdls_auth_header no_header = {0};
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    uint8_t frames[4][CCSDS_SDLS_PROTECTED_OVERHEAD + 1u];
    uint8_t clear = 0x5au;
    uint8_t output;

    init_ctx(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    init_ctx(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);

    zassert_ok(protect(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, no_header, &clear, 1u,
                       frames[0]));
    tx.keys[TEST_KEY_ID].tx_arsn = 2u;
    zassert_ok(protect(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, no_header, &clear, 1u,
                       frames[1]));
    tx.keys[TEST_KEY_ID].tx_arsn = 1u;
    zassert_ok(protect(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, no_header, &clear, 1u,
                       frames[2]));

    zassert_ok(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                       frames[0], sizeof(frames[0]), &output));
    zassert_ok(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                       frames[1], sizeof(frames[1]), &output));
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frames[2], sizeof(frames[2]), &output),
                  CCSDS_SDLS_ERR_REPLAY);
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frames[1], sizeof(frames[1]), &output),
                  CCSDS_SDLS_ERR_REPLAY);

    tx.keys[TEST_KEY_ID].tx_arsn =
        rx.sas[0].rx_arsn + CONFIG_CCSDS_SDLS_ARSN_WINDOW + 1u;
    zassert_ok(protect(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, no_header, &clear, 1u,
                       frames[3]));
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frames[3], sizeof(frames[3]), &output),
                  CCSDS_SDLS_ERR_REPLAY);
}

ZTEST(sdls_wire, test_transmit_counter_is_volatile_and_wraps_naturally)
{
    struct ccsds_sdls_auth_header no_header = {0};
    struct ccsds_sdls_ctx tx;
    uint8_t frame[CCSDS_SDLS_PROTECTED_OVERHEAD + 1u];
    uint8_t clear = 1u;
    uint32_t arsn;

    init_ctx(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    tx.keys[TEST_KEY_ID].tx_arsn = UINT32_MAX;
    zassert_ok(
        protect(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, no_header, &clear, 1u, frame));
    arsn = ccsds_sdls_iv_arsn(frame + 2u);
    zassert_equal(arsn, UINT32_MAX);
    zassert_equal(tx.keys[TEST_KEY_ID].tx_arsn, 0u);
}

ZTEST(sdls_wire, test_received_state_rejections)
{
    struct ccsds_sdls_auth_header no_header = {0};
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    uint8_t frame[CCSDS_SDLS_PROTECTED_OVERHEAD + 1u];
    uint8_t clear = 1u;

    init_ctx(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE);
    zassert_ok(
        protect(&tx, CCSDS_SDLS_SA_EP_REPLY_TX, no_header, &clear, 1u, frame));

    init_ctx(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_STOPPED, CCSDS_SDLS_KEY_ACTIVE);
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frame, sizeof(frame), &clear),
                  CCSDS_SDLS_ERR_SA_STATE);
    rx.sas[0].state = CCSDS_SDLS_SA_EXPIRED;
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frame, sizeof(frame), &clear),
                  CCSDS_SDLS_ERR_SA_STATE);
    rx.sas[0].state = CCSDS_SDLS_SA_OPERATIONAL;
    rx.keys[TEST_KEY_ID].state = CCSDS_SDLS_KEY_DEACTIVATED;
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frame, sizeof(frame), &clear),
                  CCSDS_SDLS_ERR_KEY);
    rx.keys[TEST_KEY_ID].state = CCSDS_SDLS_KEY_ACTIVE;
    rx.sas[0].key_slot = CCSDS_SDLS_KEY_SLOT_NONE;
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frame, sizeof(frame), &clear),
                  CCSDS_SDLS_ERR_KEY);

    frame[0] = 0x77u;
    frame[1] = 0x77u;
    zassert_equal(process(&rx, CCSDS_SDLS_SA_OPERATIONAL_TC_RX, no_header,
                          frame, sizeof(frame), &clear),
                  CCSDS_SDLS_ERR_UNKNOWN_SA);
}

static void *sdls_wire_setup(void)
{
    zassert_equal(psa_crypto_init(), PSA_SUCCESS);
    return NULL;
}

static void sdls_wire_before(void *fixture)
{
    ARG_UNUSED(fixture);
    import_key();
}

static void sdls_wire_after(void *fixture)
{
    ARG_UNUSED(fixture);
    zassert_equal(psa_destroy_key(test_psa_key), PSA_SUCCESS);
    test_psa_key = PSA_KEY_ID_NULL;
}

ZTEST_SUITE(sdls_wire, NULL, sdls_wire_setup, sdls_wire_before, sdls_wire_after,
            NULL);
