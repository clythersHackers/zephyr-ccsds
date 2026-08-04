#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <ccsds/ccsds_sdls.h>

BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_KEYS == 8);
BUILD_ASSERT(CONFIG_CCSDS_SDLS_SESSION_KEY_BASE == 4);
BUILD_ASSERT(CCSDS_SDLS_EP_MAX_OTAR_KEYS == 4);
BUILD_ASSERT(CCSDS_SDLS_EP_OTAR_PDU_MAX == 169);
BUILD_ASSERT(CCSDS_SDLS_EP_PLAINTEXT_MAX == 136);
BUILD_ASSERT(CCSDS_SDLS_EP_VERIFY_COMMAND_PDU_MAX == 147);
BUILD_ASSERT(CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX == 371);

static int import_calls;
static int fail_import_call = -1;
static int destroy_calls;
static psa_key_id_t last_destroyed;

psa_status_t
ccsds_sdls_ep_psa_import_key(const psa_key_attributes_t *attributes,
                             const uint8_t *data, size_t data_len,
                             psa_key_id_t *key_id)
{
    int call = import_calls++;

    if (call == fail_import_call) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    return psa_import_key(attributes, data, data_len, key_id);
}

psa_status_t ccsds_sdls_ep_psa_destroy_key(psa_key_id_t key_id)
{
    destroy_calls++;
    last_destroyed = key_id;
    return psa_destroy_key(key_id);
}

static psa_key_id_t import_aes_key(uint8_t seed, size_t key_len,
                                   psa_algorithm_t algorithm)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t bytes[CCSDS_SDLS_EP_KEY_LEN];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    for (size_t i = 0u; i < sizeof(bytes); i++) {
        bytes[i] = seed + (uint8_t)i;
    }
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, algorithm);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8u);
    zassert_equal(psa_import_key(&attributes, bytes, key_len, &key_id),
                  PSA_SUCCESS);
    memset(bytes, 0, sizeof(bytes));
    psa_reset_key_attributes(&attributes);
    return key_id;
}

static void init_master_ctx(struct ccsds_sdls_ctx *ctx, psa_key_id_t master_key,
                            psa_key_id_t alternate_master, bool with_tm_sa,
                            uint16_t tm_key_id)
{
    struct ccsds_sdls_key_init keys[2] = {
        {.psa_key_id = master_key,
         .key_id = 0u,
         .state = CCSDS_SDLS_KEY_ACTIVE},
        {.psa_key_id = alternate_master,
         .key_id = 1u,
         .state = CCSDS_SDLS_KEY_ACTIVE},
    };
    struct ccsds_sdls_sa_init sa = {
        .spi = 1u,
        .key_id = tm_key_id,
        .role = CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
        .mode = CCSDS_SDLS_MODE_GCM,
        .state = CCSDS_SDLS_SA_OPERATIONAL,
        .has_key = true,
    };

    ccsds_sdls_init(ctx, with_tm_sa ? &sa : NULL, with_tm_sa ? 1u : 0u, keys,
                    alternate_master == PSA_KEY_ID_NULL ? 1u : 2u);
}

static size_t make_otar(psa_key_id_t master, uint16_t master_id,
                        const uint16_t *destinations, size_t count,
                        uint8_t seed, uint8_t *pdu)
{
    uint8_t plaintext[CCSDS_SDLS_EP_PLAINTEXT_MAX];
    size_t plaintext_len = count * CCSDS_SDLS_EP_OTAR_BLOCK_LEN;
    size_t data_len =
        2u + CCSDS_SDLS_IV_LEN + plaintext_len + CCSDS_SDLS_TAG_LEN;
    size_t output_len;

    pdu[0] = CCSDS_SDLS_EP_OTAR;
    sys_put_be16(data_len * 8u, pdu + 1u);
    sys_put_be16(master_id, pdu + 3u);
    for (size_t i = 0u; i < CCSDS_SDLS_IV_LEN; i++) {
        pdu[5u + i] = 0x80u + (uint8_t)i;
    }
    for (size_t i = 0u; i < count; i++) {
        size_t offset = i * CCSDS_SDLS_EP_OTAR_BLOCK_LEN;

        sys_put_be16(destinations[i], plaintext + offset);
        for (size_t j = 0u; j < CCSDS_SDLS_EP_KEY_LEN; j++) {
            plaintext[offset + 2u + j] = seed + (uint8_t)i + (uint8_t)j;
        }
    }
    zassert_equal(
        psa_aead_encrypt(master, PSA_ALG_GCM, pdu + 5u, CCSDS_SDLS_IV_LEN, pdu,
                         5u, plaintext, plaintext_len, pdu + 17u,
                         plaintext_len + CCSDS_SDLS_TAG_LEN, &output_len),
        PSA_SUCCESS);
    zassert_equal(output_len, plaintext_len + CCSDS_SDLS_TAG_LEN);
    memset(plaintext, 0, sizeof(plaintext));
    return CCSDS_SDLS_EP_HEADER_LEN + data_len;
}

static void assert_zero(const uint8_t *data, size_t len)
{
    for (size_t i = 0u; i < len; i++) {
        zassert_equal(data[i], 0u, "byte %zu was not wiped", i);
    }
}

static void destroy_ctx_sessions(struct ccsds_sdls_ctx *ctx)
{
    for (size_t i = CONFIG_CCSDS_SDLS_SESSION_KEY_BASE;
         i < CONFIG_CCSDS_SDLS_MAX_KEYS; i++) {
        if (ctx->keys[i].psa_key_id != PSA_KEY_ID_NULL) {
            zassert_equal(psa_destroy_key(ctx->keys[i].psa_key_id),
                          PSA_SUCCESS);
            ctx->keys[i].psa_key_id = PSA_KEY_ID_NULL;
        }
    }
}

ZTEST(sdls_ep_codec, test_exact_key_command_vectors)
{
    struct ccsds_sdls_ep_key_command decoded;
    struct ccsds_sdls_ep_key_command command = {.key_ids = {0x1234u, 0x5678u},
                                                .key_count = 2u};
    static const uint8_t activation[] = {0x02, 0x00, 0x20, 0x12,
                                         0x34, 0x56, 0x78};
    static const uint8_t deactivation[] = {0x03, 0x00, 0x20, 0x12,
                                           0x34, 0x56, 0x78};
    uint8_t encoded[sizeof(activation)];

    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_ACTIVATION, &command,
                                     encoded, sizeof(encoded));
    zassert_mem_equal(encoded, activation, sizeof(activation));
    zassert_ok(ccsds_sdls_ep_key_command_decode(activation, sizeof(activation),
                                                CCSDS_SDLS_EP_KEY_ACTIVATION,
                                                &decoded));
    zassert_equal(decoded.key_count, 2u);
    zassert_mem_equal(decoded.key_ids, command.key_ids, 4u);

    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_DEACTIVATION, &command,
                                     encoded, sizeof(encoded));
    zassert_mem_equal(encoded, deactivation, sizeof(deactivation));
}

ZTEST(sdls_ep_codec, test_exact_key_inventory_vectors)
{
    const struct ccsds_sdls_ep_key_inventory_command command = {
        .first_key_id = 0x0004u,
        .last_key_id = 0x000bu,
    };
    const struct ccsds_sdls_ep_key_inventory_reply reply = {
        .entries = {{.key_id = 0x0004u, .state = CCSDS_SDLS_KEY_PREACTIVE},
                    {.key_id = 0x0007u, .state = CCSDS_SDLS_KEY_ACTIVE},
                    {.key_id = 0x000bu,
                     .state = CCSDS_SDLS_KEY_DEACTIVATED}},
        .key_count = 3u,
    };
    static const uint8_t expected_command[] = {
        0x07, 0x00, 0x20, 0x00, 0x04, 0x00, 0x0b,
    };
    static const uint8_t expected_reply[] = {
        0x87, 0x00, 0x58, 0x00, 0x03, 0x00, 0x04,
        0x00, 0x00, 0x07, 0x01, 0x00, 0x0b, 0x02,
    };
    struct ccsds_sdls_ep_key_inventory_command decoded_command;
    struct ccsds_sdls_ep_key_inventory_reply decoded_reply;
    uint8_t encoded_command[sizeof(expected_command)];
    uint8_t encoded_reply[sizeof(expected_reply)];
    size_t encoded_reply_len = 0u;

    ccsds_sdls_ep_key_inventory_command_encode(
        &command, encoded_command, sizeof(encoded_command));
    zassert_mem_equal(encoded_command, expected_command,
                      sizeof(expected_command));
    zassert_ok(ccsds_sdls_ep_key_inventory_command_decode(
        expected_command, sizeof(expected_command), &decoded_command));
    zassert_equal(decoded_command.first_key_id, command.first_key_id);
    zassert_equal(decoded_command.last_key_id, command.last_key_id);

    zassert_ok(ccsds_sdls_ep_key_inventory_reply_encode(
        &reply, encoded_reply, sizeof(encoded_reply), &encoded_reply_len));
    zassert_equal(encoded_reply_len, sizeof(expected_reply));
    zassert_mem_equal(encoded_reply, expected_reply, sizeof(expected_reply));
    zassert_ok(ccsds_sdls_ep_key_inventory_reply_decode(
        expected_reply, sizeof(expected_reply), &decoded_reply));
    zassert_equal(decoded_reply.key_count, reply.key_count);
    zassert_mem_equal(decoded_reply.entries, reply.entries,
                      reply.key_count * sizeof(reply.entries[0]));
}

ZTEST(sdls_ep_codec, test_key_inventory_rejects_malformed_wire)
{
    struct ccsds_sdls_ep_key_inventory_command command;
    struct ccsds_sdls_ep_key_inventory_reply reply;
    uint8_t reversed[] = {0x07, 0x00, 0x20, 0x00, 0x05, 0x00, 0x04};
    uint8_t wrong_type[] = {0x87, 0x00, 0x20, 0x00, 0x04, 0x00, 0x05};
    uint8_t wrong_group[] = {0x17, 0x00, 0x20, 0x00, 0x04, 0x00, 0x05};
    uint8_t wrong_procedure[] = {0x04, 0x00, 0x20, 0x00, 0x04, 0x00, 0x05};
    uint8_t wrong_bits[] = {0x07, 0x00, 0x18, 0x00, 0x04, 0x00, 0x05};
    uint8_t bad_count[] = {0x87, 0x00, 0x10, 0x00, 0x01};
    uint8_t bad_state[] = {0x87, 0x00, 0x28, 0x00,
                           0x01, 0x00, 0x04, 0x03};
    uint8_t duplicate[] = {0x87, 0x00, 0x40, 0x00, 0x02, 0x00,
                           0x04, 0x00, 0x00, 0x04, 0x01};

    for (size_t len = 0u; len < sizeof(reversed); len++) {
        zassert_not_equal(ccsds_sdls_ep_key_inventory_command_decode(
                              reversed, len, &command),
                          0);
    }
    zassert_equal(ccsds_sdls_ep_key_inventory_command_decode(
                      reversed, sizeof(reversed), &command),
                  CCSDS_SDLS_ERR_KEY);
    zassert_equal(ccsds_sdls_ep_key_inventory_command_decode(
                      wrong_type, sizeof(wrong_type), &command),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_equal(ccsds_sdls_ep_key_inventory_command_decode(
                      wrong_group, sizeof(wrong_group), &command),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_equal(ccsds_sdls_ep_key_inventory_command_decode(
                      wrong_procedure, sizeof(wrong_procedure), &command),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_equal(ccsds_sdls_ep_key_inventory_command_decode(
                      wrong_bits, sizeof(wrong_bits), &command),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_ep_key_inventory_reply_decode(
                      bad_count, sizeof(bad_count), &reply),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_ep_key_inventory_reply_decode(
                      bad_state, sizeof(bad_state), &reply),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_ep_key_inventory_reply_decode(
                      duplicate, sizeof(duplicate), &reply),
                  CCSDS_SDLS_ERR_FORMAT);
}

ZTEST(sdls_ep_codec, test_exact_verification_vectors)
{
    struct ccsds_sdls_ep_verify_command command = {.key_count = 1u};
    struct ccsds_sdls_ep_verify_command decoded_command;
    struct ccsds_sdls_ep_verify_reply reply = {.key_count = 1u};
    struct ccsds_sdls_ep_verify_reply decoded_reply;
    uint8_t command_wire[21];
    uint8_t reply_wire[49];
    uint8_t expected_command[21] = {0x04, 0x00, 0x90, 0x12, 0x34};
    uint8_t expected_reply[49] = {0x84, 0x01, 0x70, 0x12, 0x34};

    command.entries[0].key_id = 0x1234u;
    reply.entries[0].key_id = 0x1234u;
    for (size_t i = 0u; i < CCSDS_SDLS_EP_CHALLENGE_LEN; i++) {
        command.entries[0].challenge[i] = (uint8_t)i;
        expected_command[5u + i] = (uint8_t)i;
        reply.entries[0].encrypted_challenge[i] = 0x20u + (uint8_t)i;
        reply.entries[0].tag[i] = 0x40u + (uint8_t)i;
        expected_reply[17u + i] = 0x20u + (uint8_t)i;
        expected_reply[33u + i] = 0x40u + (uint8_t)i;
    }
    for (size_t i = 0u; i < CCSDS_SDLS_IV_LEN; i++) {
        reply.entries[0].iv[i] = 0x10u + (uint8_t)i;
        expected_reply[5u + i] = 0x10u + (uint8_t)i;
    }

    ccsds_sdls_ep_verify_command_encode(&command, command_wire,
                                        sizeof(command_wire));
    zassert_mem_equal(command_wire, expected_command, sizeof(command_wire));
    zassert_ok(ccsds_sdls_ep_verify_command_decode(
        command_wire, sizeof(command_wire), &decoded_command));
    zassert_mem_equal(&decoded_command.entries[0], &command.entries[0],
                      sizeof(command.entries[0]));

    ccsds_sdls_ep_verify_reply_encode(&reply, reply_wire, sizeof(reply_wire));
    zassert_mem_equal(reply_wire, expected_reply, sizeof(reply_wire));
    zassert_ok(ccsds_sdls_ep_verify_reply_decode(reply_wire, sizeof(reply_wire),
                                                 &decoded_reply));
    zassert_equal(decoded_reply.entries[0].key_id, 0x1234u);
    zassert_mem_equal(decoded_reply.entries[0].iv, reply.entries[0].iv,
                      CCSDS_SDLS_IV_LEN);
}

ZTEST(sdls_ep_codec, test_exact_otar_ciphertext_vector)
{
    struct ccsds_sdls_ep_otar otar = {.master_key_id = 0x1234u,
                                      .key_count = 1u};
    struct ccsds_sdls_ep_otar decoded;
    uint8_t expected[67] = {0x01, 0x02, 0x00, 0x12, 0x34};
    uint8_t encoded[sizeof(expected)];

    for (size_t i = 0u; i < CCSDS_SDLS_IV_LEN; i++) {
        otar.iv[i] = 0x10u + (uint8_t)i;
        expected[5u + i] = 0x10u + (uint8_t)i;
    }
    for (size_t i = 0u; i < CCSDS_SDLS_EP_OTAR_BLOCK_LEN; i++) {
        otar.encrypted_key_blocks[i] = 0x20u + (uint8_t)i;
        expected[17u + i] = 0x20u + (uint8_t)i;
    }
    for (size_t i = 0u; i < CCSDS_SDLS_TAG_LEN; i++) {
        otar.tag[i] = 0x50u + (uint8_t)i;
        expected[51u + i] = 0x50u + (uint8_t)i;
    }
    ccsds_sdls_ep_otar_encode(&otar, encoded, sizeof(encoded));
    zassert_mem_equal(encoded, expected, sizeof(expected));
    zassert_ok(ccsds_sdls_ep_otar_decode(encoded, sizeof(encoded), &decoded));
    zassert_equal(decoded.master_key_id, otar.master_key_id);
    zassert_equal(decoded.key_count, 1u);
    zassert_mem_equal(decoded.encrypted_key_blocks, otar.encrypted_key_blocks,
                      CCSDS_SDLS_EP_OTAR_BLOCK_LEN);
}

ZTEST(sdls_ep_codec, test_malformed_unknown_nested_and_trailing_pdus)
{
    struct ccsds_sdls_ep_pdu pdu;
    struct ccsds_sdls_ep_key_command command;
    uint8_t activation[] = {0x02, 0x00, 0x10, 0x00, 0x04};
    uint8_t nested[] = {0x02, 0x00, 0x18, 0x02, 0x00, 0x00};

    for (size_t len = 0u; len < sizeof(activation); len++) {
        zassert_not_equal(
            ccsds_sdls_ep_key_command_decode(
                activation, len, CCSDS_SDLS_EP_KEY_ACTIVATION, &command),
            0);
    }
    activation[1] = 0u;
    activation[2] = 0x11u;
    zassert_equal(
        ccsds_sdls_ep_pdu_decode(activation, sizeof(activation), &pdu),
        CCSDS_SDLS_ERR_FORMAT);
    activation[2] = 0x08u;
    zassert_equal(
        ccsds_sdls_ep_pdu_decode(activation, sizeof(activation), &pdu),
        CCSDS_SDLS_ERR_FORMAT);
    activation[0] = 0x05u;
    zassert_equal(ccsds_sdls_ep_pdu_decode(activation, 4u, &pdu),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    activation[0] = 0x42u;
    zassert_equal(ccsds_sdls_ep_pdu_decode(activation, 4u, &pdu),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    activation[0] = 0x12u;
    zassert_equal(ccsds_sdls_ep_pdu_decode(activation, 4u, &pdu),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_equal(ccsds_sdls_ep_key_command_decode(nested, sizeof(nested),
                                                   CCSDS_SDLS_EP_KEY_ACTIVATION,
                                                   &command),
                  CCSDS_SDLS_ERR_FORMAT);
}

ZTEST(sdls_ep_otar, test_single_and_maximum_atomic_otar)
{
    psa_key_id_t master = import_aes_key(0x10u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx ctx;
    uint16_t single[] = {4u};
    uint16_t maximum[] = {4u, 5u, 6u, 7u};
    uint8_t pdu[CCSDS_SDLS_EP_OTAR_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_PLAINTEXT_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    size_t len;

    init_master_ctx(&ctx, master, PSA_KEY_ID_NULL, false, 0u);
    memset(scratch, 0xa5, sizeof(scratch));
    len = make_otar(master, 0u, single, 1u, 0x40u, pdu);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace));
    zassert_not_equal(ctx.keys[4].psa_key_id, PSA_KEY_ID_NULL);
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_PREACTIVE);
    zassert_equal(ctx.keys[4].tx_arsn, 0u);
    assert_zero(scratch, sizeof(scratch));

    ctx.keys[4].state = CCSDS_SDLS_KEY_ACTIVE;
    single[0] = 5u;
    len = make_otar(ctx.keys[4].psa_key_id, 4u, single, 1u, 0x41u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_KEY);
    zassert_equal(ctx.keys[5].psa_key_id, PSA_KEY_ID_NULL);
    destroy_ctx_sessions(&ctx);

    init_master_ctx(&ctx, master, PSA_KEY_ID_NULL, false, 0u);
    len = make_otar(master, 0u, maximum, ARRAY_SIZE(maximum), 0x50u, pdu);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace));
    for (size_t i = 4u; i < 8u; i++) {
        zassert_not_equal(ctx.keys[i].psa_key_id, PSA_KEY_ID_NULL);
        zassert_equal(ctx.keys[i].state, CCSDS_SDLS_KEY_PREACTIVE);
    }
    destroy_ctx_sessions(&ctx);
    zassert_equal(psa_destroy_key(master), PSA_SUCCESS);
}

ZTEST(sdls_ep_otar, test_tamper_wrong_master_duplicate_and_session_master)
{
    psa_key_id_t master = import_aes_key(0x20u, 32u, PSA_ALG_GCM);
    psa_key_id_t wrong_master = import_aes_key(0x60u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx ctx;
    uint16_t ids[] = {4u, 5u};
    uint16_t duplicate[] = {4u, 4u};
    uint8_t pdu[CCSDS_SDLS_EP_OTAR_PDU_MAX];
    uint8_t original[sizeof(pdu)];
    uint8_t scratch[CCSDS_SDLS_EP_PLAINTEXT_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    size_t len = make_otar(master, 0u, ids, ARRAY_SIZE(ids), 0x30u, pdu);

    init_master_ctx(&ctx, master, wrong_master, false, 0u);
    len = make_otar(master, 0u, ids, ARRAY_SIZE(ids), 0x30u, pdu);
    memcpy(original, pdu, len);
    const size_t tamper_offsets[] = {17u, len - 1u, 5u};
    for (size_t i = 0u; i < ARRAY_SIZE(tamper_offsets); i++) {
        memcpy(pdu, original, len);
        pdu[tamper_offsets[i]] ^= 1u;
        import_calls = 0;
        zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                      CCSDS_SDLS_ERR_AUTHENTICATION);
        zassert_equal(import_calls, 0);
        zassert_equal(ctx.keys[4].psa_key_id, PSA_KEY_ID_NULL);
        assert_zero(scratch, sizeof(scratch));
    }
    memcpy(pdu, original, len);
    pdu[4] = 1u;
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_AUTHENTICATION);
    memcpy(pdu, original, len);
    pdu[0] = CCSDS_SDLS_EP_KEY_ACTIVATION;
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_UNSUPPORTED);

    len = make_otar(master, 0u, duplicate, ARRAY_SIZE(duplicate), 0x30u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ctx.keys[4].psa_key_id, PSA_KEY_ID_NULL);

    len = make_otar(master, 0u, ids, 1u, 0x30u, pdu);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace));
    ctx.keys[4].state = CCSDS_SDLS_KEY_ACTIVE;
    len = make_otar(ctx.keys[4].psa_key_id, 4u, &ids[1], 1u, 0x31u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_KEY);
    zassert_equal(ctx.keys[5].psa_key_id, PSA_KEY_ID_NULL);
    len = make_otar(master, 0u, ids, 1u, 0x32u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_KEY_STATE);
    destroy_ctx_sessions(&ctx);
    zassert_equal(psa_destroy_key(master), PSA_SUCCESS);
    zassert_equal(psa_destroy_key(wrong_master), PSA_SUCCESS);
}

ZTEST(sdls_ep_otar, test_replaces_only_non_active_session_keys)
{
    psa_key_id_t master = import_aes_key(0x12u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx ctx;
    uint16_t destination[] = {4u};
    uint16_t pair[] = {4u, 5u};
    uint8_t pdu[CCSDS_SDLS_EP_OTAR_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_PLAINTEXT_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t old_key;
    size_t len;

    init_master_ctx(&ctx, master, PSA_KEY_ID_NULL, false, 0u);
    len = make_otar(master, 0u, destination, 1u, 0x40u, pdu);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace));
    old_key = ctx.keys[4].psa_key_id;

    len = make_otar(master, 0u, destination, 1u, 0x50u, pdu);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace));
    zassert_not_equal(ctx.keys[4].psa_key_id, old_key);
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_PREACTIVE);
    zassert_equal(psa_get_key_attributes(old_key, &attributes),
                  PSA_ERROR_INVALID_HANDLE);

    old_key = ctx.keys[4].psa_key_id;
    ctx.keys[4].state = CCSDS_SDLS_KEY_DEACTIVATED;
    len = make_otar(master, 0u, destination, 1u, 0x60u, pdu);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace));
    zassert_not_equal(ctx.keys[4].psa_key_id, old_key);
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_PREACTIVE);
    zassert_equal(psa_get_key_attributes(old_key, &attributes),
                  PSA_ERROR_INVALID_HANDLE);

    len = make_otar(master, 0u, &pair[1], 1u, 0x70u, pdu);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace));
    ctx.keys[4].state = CCSDS_SDLS_KEY_DEACTIVATED;
    ctx.keys[5].state = CCSDS_SDLS_KEY_DEACTIVATED;
    psa_key_id_t old_pair[] = {ctx.keys[4].psa_key_id,
                               ctx.keys[5].psa_key_id};

    import_calls = 0;
    fail_import_call = 1;
    len = make_otar(master, 0u, pair, ARRAY_SIZE(pair), 0x80u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_PSA);
    fail_import_call = -1;
    zassert_equal(ctx.keys[4].psa_key_id, old_pair[0]);
    zassert_equal(ctx.keys[5].psa_key_id, old_pair[1]);
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_DEACTIVATED);
    zassert_equal(ctx.keys[5].state, CCSDS_SDLS_KEY_DEACTIVATED);

    destroy_ctx_sessions(&ctx);
    zassert_equal(psa_destroy_key(master), PSA_SUCCESS);
}

ZTEST(sdls_ep_otar, test_invalid_destinations_master_attributes_and_rollback)
{
    psa_key_id_t master = import_aes_key(0x11u, 32u, PSA_ALG_GCM);
    psa_key_id_t short_master = import_aes_key(0x22u, 16u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx ctx;
    uint16_t bad_master_destination[] = {0u};
    uint16_t bad_range[] = {CONFIG_CCSDS_SDLS_MAX_KEYS};
    uint16_t ids[] = {4u, 5u};
    uint8_t pdu[CCSDS_SDLS_EP_OTAR_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_PLAINTEXT_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t len;

    init_master_ctx(&ctx, master, PSA_KEY_ID_NULL, false, 0u);
    len = make_otar(master, 0u, bad_master_destination, 1u, 1u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_KEY);
    len = make_otar(master, 0u, bad_range, 1u, 1u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_KEY);

    init_master_ctx(&ctx, short_master, PSA_KEY_ID_NULL, false, 0u);
    len = make_otar(short_master, 0u, ids, 1u, 1u, pdu);
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_KEY);

    init_master_ctx(&ctx, master, PSA_KEY_ID_NULL, false, 0u);
    len = make_otar(master, 0u, ids, ARRAY_SIZE(ids), 1u, pdu);
    import_calls = 0;
    destroy_calls = 0;
    fail_import_call = 1;
    memset(scratch, 0xa5, sizeof(scratch));
    zassert_equal(ccsds_sdls_ep_process_otar(&ctx, pdu, len, workspace),
                  CCSDS_SDLS_ERR_PSA);
    fail_import_call = -1;
    zassert_equal(import_calls, 2);
    zassert_equal(destroy_calls, 1);
    zassert_equal(ctx.keys[4].psa_key_id, PSA_KEY_ID_NULL);
    zassert_equal(ctx.keys[5].psa_key_id, PSA_KEY_ID_NULL);
    zassert_equal(psa_get_key_attributes(last_destroyed, &attributes),
                  PSA_ERROR_INVALID_HANDLE);
    assert_zero(scratch, sizeof(scratch));
    zassert_equal(psa_destroy_key(master), PSA_SUCCESS);
    zassert_equal(psa_destroy_key(short_master), PSA_SUCCESS);
}

ZTEST(sdls_ep_lifecycle, test_atomic_activation_deactivation_and_repetition)
{
    psa_key_id_t master = import_aes_key(0x10u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx ctx;
    uint16_t ids[] = {4u, 5u};
    uint8_t otar[CCSDS_SDLS_EP_OTAR_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_PLAINTEXT_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    struct ccsds_sdls_ep_key_command command = {.key_ids = {4u, 5u},
                                                .key_count = 2u};
    uint8_t wire[CCSDS_SDLS_EP_KEY_COMMAND_PDU_MAX];
    size_t otar_len = make_otar(master, 0u, ids, 2u, 1u, otar);

    init_master_ctx(&ctx, master, PSA_KEY_ID_NULL, false, 0u);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, otar, otar_len, workspace));
    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_ACTIVATION, &command,
                                     wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_key_activation(&ctx, wire, 7u));
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_ACTIVE);
    zassert_equal(ccsds_sdls_ep_process_key_activation(&ctx, wire, 7u),
                  CCSDS_SDLS_ERR_KEY_STATE);

    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_DEACTIVATION, &command,
                                     wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_key_deactivation(&ctx, wire, 7u));
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_DEACTIVATED);
    zassert_equal(ccsds_sdls_ep_process_key_deactivation(&ctx, wire, 7u),
                  CCSDS_SDLS_ERR_KEY_STATE);

    ctx.keys[4].state = CCSDS_SDLS_KEY_PREACTIVE;
    command.key_ids[0] = 4u;
    command.key_ids[1] = 7u;
    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_ACTIVATION, &command,
                                     wire, sizeof(wire));
    zassert_equal(ccsds_sdls_ep_process_key_activation(&ctx, wire, 7u),
                  CCSDS_SDLS_ERR_KEY);
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_PREACTIVE);
    destroy_ctx_sessions(&ctx);
    zassert_equal(psa_destroy_key(master), PSA_SUCCESS);
}

ZTEST(sdls_ep_inventory, test_fixed_table_inventory_is_authenticated_and_read_only)
{
    psa_key_id_t master0 = import_aes_key(0x10u, 32u, PSA_ALG_GCM);
    psa_key_id_t master1 = import_aes_key(0x20u, 32u, PSA_ALG_GCM);
    psa_key_id_t session5 = import_aes_key(0x50u, 32u, PSA_ALG_GCM);
    psa_key_id_t session6 = import_aes_key(0x60u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_key_inventory_command command = {
        .first_key_id = 0u,
        .last_key_id = CONFIG_CCSDS_SDLS_MAX_KEYS - 1u,
    };
    struct ccsds_sdls_ep_key_inventory_reply decoded;
    struct ccsds_sdls_key keys_before[CONFIG_CCSDS_SDLS_MAX_KEYS];
    struct ccsds_sdls_sa sas_before[CONFIG_CCSDS_SDLS_MAX_SA];
    uint8_t wire[CCSDS_SDLS_EP_KEY_INVENTORY_COMMAND_PDU_LEN];
    uint8_t otar[CCSDS_SDLS_EP_OTAR_PDU_MAX];
    uint8_t reply[CCSDS_SDLS_EP_KEY_INVENTORY_REPLY_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_WORKSPACE_MIN];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    size_t reply_len = 0x55u;
    uint16_t destination = 4u;

    init_master_ctx(&ctx, master0, master1, false, 0u);
    size_t otar_len = make_otar(master0, 0u, &destination, 1u, 0x40u, otar);
    zassert_ok(ccsds_sdls_ep_process_otar(&ctx, otar, otar_len, workspace));
    ctx.keys[5].psa_key_id = session5;
    ctx.keys[5].state = CCSDS_SDLS_KEY_ACTIVE;
    ctx.keys[6].psa_key_id = session6;
    ctx.keys[6].state = CCSDS_SDLS_KEY_DEACTIVATED;
    ccsds_sdls_ep_key_inventory_command_encode(&command, wire, sizeof(wire));

    memset(reply, 0xa5, sizeof(reply));
    zassert_equal(ccsds_sdls_ep_process_key_inventory(
                      &ctx, wire, sizeof(wire), reply, sizeof(reply),
                      &reply_len),
                  CCSDS_SDLS_ERR_AUTHENTICATION);
    zassert_equal(reply_len, 0x55u);
    zassert_equal(reply[0], 0xa5u);

    ctx.authenticated_rx_valid = true;
    memcpy(keys_before, ctx.keys, sizeof(keys_before));
    memcpy(sas_before, ctx.sas, sizeof(sas_before));
    reply_len = 0x55u;
    zassert_equal(ccsds_sdls_ep_process_key_inventory(
                      &ctx, wire, sizeof(wire), reply, 19u, &reply_len),
                  CCSDS_SDLS_ERR_CAPACITY);
    zassert_equal(reply_len, 0x55u);
    zassert_equal(reply[0], 0xa5u);

    ctx.authenticated_rx_spi = 1u;
    ctx.authenticated_rx_arsn = 42u;
    reply_len = 0u;
    zassert_ok(ccsds_sdls_ep_process_pdu(
        &ctx, wire, sizeof(wire), workspace, reply, sizeof(reply), &reply_len));
    zassert_equal(reply_len, 20u);
    zassert_ok(ccsds_sdls_ep_key_inventory_reply_decode(reply, reply_len,
                                                        &decoded));
    zassert_equal(decoded.key_count, 5u);
    zassert_equal(decoded.entries[0].key_id, 0u);
    zassert_equal(decoded.entries[0].state, CCSDS_SDLS_KEY_ACTIVE);
    zassert_equal(decoded.entries[1].key_id, 1u);
    zassert_equal(decoded.entries[2].key_id, 4u);
    zassert_equal(decoded.entries[2].state, CCSDS_SDLS_KEY_PREACTIVE);
    zassert_equal(decoded.entries[3].key_id, 5u);
    zassert_equal(decoded.entries[3].state, CCSDS_SDLS_KEY_ACTIVE);
    zassert_equal(decoded.entries[4].key_id, 6u);
    zassert_equal(decoded.entries[4].state, CCSDS_SDLS_KEY_DEACTIVATED);
    zassert_mem_equal(ctx.keys, keys_before, sizeof(keys_before));
    zassert_mem_equal(ctx.sas, sas_before, sizeof(sas_before));

    struct ccsds_sdls_ep_key_command lifecycle = {
        .key_ids = {4u},
        .key_count = 1u,
    };
    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_ACTIVATION, &lifecycle,
                                     wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_key_activation(
        &ctx, wire, CCSDS_SDLS_EP_HEADER_LEN + 2u));
    lifecycle.key_ids[0] = 5u;
    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_DEACTIVATION, &lifecycle,
                                     wire, sizeof(wire));
    zassert_ok(
        ccsds_sdls_ep_process_key_deactivation(
            &ctx, wire, CCSDS_SDLS_EP_HEADER_LEN + 2u));
    command.first_key_id = 4u;
    command.last_key_id = 5u;
    ccsds_sdls_ep_key_inventory_command_encode(&command, wire, sizeof(wire));
    ctx.authenticated_rx_valid = true;
    reply_len = 0u;
    zassert_ok(ccsds_sdls_ep_process_key_inventory(
        &ctx, wire, sizeof(wire), reply, sizeof(reply), &reply_len));
    zassert_ok(ccsds_sdls_ep_key_inventory_reply_decode(reply, reply_len,
                                                        &decoded));
    zassert_equal(decoded.entries[0].state, CCSDS_SDLS_KEY_ACTIVE);
    zassert_equal(decoded.entries[1].state, CCSDS_SDLS_KEY_DEACTIVATED);

    destroy_ctx_sessions(&ctx);
    zassert_equal(psa_destroy_key(master0), PSA_SUCCESS);
    zassert_equal(psa_destroy_key(master1), PSA_SUCCESS);
}

ZTEST(sdls_ep_inventory, test_single_undefined_and_out_of_range_inventory)
{
    psa_key_id_t master = import_aes_key(0x10u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_key_inventory_command command = {
        .first_key_id = 7u,
        .last_key_id = 7u,
    };
    struct ccsds_sdls_ep_key_inventory_reply decoded;
    uint8_t wire[CCSDS_SDLS_EP_KEY_INVENTORY_COMMAND_PDU_LEN];
    uint8_t reply[CCSDS_SDLS_EP_KEY_INVENTORY_REPLY_PDU_MAX];
    uint8_t reply_in_command_direction[] = {0x87, 0x00, 0x10, 0x00, 0x00};
    uint8_t scratch[CCSDS_SDLS_EP_WORKSPACE_MIN];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    size_t reply_len = 0u;

    init_master_ctx(&ctx, master, PSA_KEY_ID_NULL, false, 0u);
    ctx.authenticated_rx_valid = true;
    ccsds_sdls_ep_key_inventory_command_encode(&command, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_key_inventory(
        &ctx, wire, sizeof(wire), reply, sizeof(reply), &reply_len));
    zassert_equal(reply_len, 5u);
    zassert_ok(ccsds_sdls_ep_key_inventory_reply_decode(reply, reply_len,
                                                        &decoded));
    zassert_equal(decoded.key_count, 0u);

    command.first_key_id = CONFIG_CCSDS_SDLS_MAX_KEYS;
    command.last_key_id = CONFIG_CCSDS_SDLS_MAX_KEYS;
    ccsds_sdls_ep_key_inventory_command_encode(&command, wire, sizeof(wire));
    reply_len = 0x55u;
    zassert_equal(ccsds_sdls_ep_process_key_inventory(
                      &ctx, wire, sizeof(wire), reply, sizeof(reply),
                      &reply_len),
                  CCSDS_SDLS_ERR_KEY);
    zassert_equal(reply_len, 0x55u);

    ctx.authenticated_rx_valid = true;
    reply_len = 0x55u;
    zassert_equal(ccsds_sdls_ep_process_pdu(
                      &ctx, reply_in_command_direction,
                      sizeof(reply_in_command_direction), workspace, reply,
                      sizeof(reply), &reply_len),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_equal(reply_len, 0x55u);
    zassert_equal(psa_destroy_key(master), PSA_SUCCESS);
}

ZTEST(sdls_ep_rollover, test_upload_verify_activate_and_operational_use)
{
    psa_key_id_t master = import_aes_key(0x10u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_ctx recipient;
    struct ccsds_sdls_ctx initiator;
    uint16_t destination[] = {6u};
    uint8_t otar[CCSDS_SDLS_EP_OTAR_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    struct ccsds_sdls_ep_verify_command verify = {.key_count = 1u};
    uint8_t verify_wire[CCSDS_SDLS_EP_VERIFY_COMMAND_PDU_MAX];
    uint8_t verify_reply[CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX];
    struct ccsds_sdls_ep_key_command activate = {.key_ids = {6u},
                                                 .key_count = 1u};
    uint8_t activate_wire[CCSDS_SDLS_EP_KEY_COMMAND_PDU_MAX];
    uint8_t protected_a[CCSDS_SDLS_PROTECTED_OVERHEAD + 1u];
    uint8_t protected_b[CCSDS_SDLS_PROTECTED_OVERHEAD + 1u];
    uint8_t frame_scratch[CCSDS_SDLS_PROTECTED_OVERHEAD + 1u];
    struct ccsds_sdls_workspace frame_workspace = {frame_scratch,
                                                   sizeof(frame_scratch)};
    struct ccsds_sdls_auth_header no_header = {0};
    uint8_t clear = 0x5au;
    size_t otar_len = make_otar(master, 0u, destination, 1u, 0x70u, otar);
    size_t verify_len =
        CCSDS_SDLS_EP_HEADER_LEN + CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN;
    size_t reply_len =
        CCSDS_SDLS_EP_HEADER_LEN + CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN;

    init_master_ctx(&recipient, master, PSA_KEY_ID_NULL, true, 6u);
    zassert_ok(
        ccsds_sdls_ep_process_otar(&recipient, otar, otar_len, workspace));
    zassert_equal(recipient.keys[6].tx_arsn, 0u);

    ccsds_sdls_init(&initiator, NULL, 0u, NULL, 0u);
    initiator.keys[6] = recipient.keys[6];
    for (size_t i = 0u; i < CCSDS_SDLS_EP_CHALLENGE_LEN; i++) {
        verify.entries[0].challenge[i] = 0xa0u + (uint8_t)i;
    }
    verify.entries[0].key_id = 6u;
    ccsds_sdls_ep_verify_command_encode(&verify, verify_wire,
                                        sizeof(verify_wire));
    memset(verify_reply, 0xa5, sizeof(verify_reply));
    zassert_ok(ccsds_sdls_ep_process_key_verification(
        &recipient, verify_wire, verify_len, workspace, verify_reply,
        sizeof(verify_reply)));
    zassert_ok(ccsds_sdls_ep_check_key_verification(&initiator, verify_wire,
                                                    verify_len, verify_reply,
                                                    reply_len, workspace));
    zassert_equal(recipient.keys[6].tx_arsn, 1u);

    ccsds_sdls_ep_key_command_encode(CCSDS_SDLS_EP_KEY_ACTIVATION, &activate,
                                     activate_wire, sizeof(activate_wire));
    zassert_ok(ccsds_sdls_ep_process_key_activation(
        &recipient, activate_wire, CCSDS_SDLS_EP_HEADER_LEN + 2u));
    zassert_ok(ccsds_sdls_apply_security(
        &recipient, CCSDS_SDLS_SA_OPERATIONAL_TM_TX, 1u, no_header, &clear, 1u,
        frame_workspace, protected_a, sizeof(protected_a)));
    zassert_ok(ccsds_sdls_apply_security(
        &recipient, CCSDS_SDLS_SA_OPERATIONAL_TM_TX, 1u, no_header, &clear, 1u,
        frame_workspace, protected_b, sizeof(protected_b)));
    zassert_not_equal(
        memcmp(protected_a + 2u, protected_b + 2u, CCSDS_SDLS_IV_LEN), 0);
    zassert_equal(ccsds_sdls_iv_arsn(protected_a + 2u), 1u);
    zassert_equal(ccsds_sdls_iv_arsn(protected_b + 2u), 2u);

    recipient.keys[6].state = CCSDS_SDLS_KEY_DEACTIVATED;
    zassert_equal(
        ccsds_sdls_apply_security(&recipient, CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
                                  1u, no_header, &clear, 1u, frame_workspace,
                                  protected_a, sizeof(protected_a)),
        CCSDS_SDLS_ERR_KEY);
    destroy_ctx_sessions(&recipient);
    zassert_equal(psa_destroy_key(master), PSA_SUCCESS);
}

ZTEST(sdls_ep_verification, test_wrong_key_and_tampered_reply)
{
    psa_key_id_t good = import_aes_key(0x10u, 32u, PSA_ALG_GCM);
    psa_key_id_t wrong = import_aes_key(0x20u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_key_init good_init = {
        .psa_key_id = good, .key_id = 4u, .state = CCSDS_SDLS_KEY_PREACTIVE};
    struct ccsds_sdls_key_init wrong_init = {
        .psa_key_id = wrong, .key_id = 4u, .state = CCSDS_SDLS_KEY_PREACTIVE};
    struct ccsds_sdls_ctx recipient;
    struct ccsds_sdls_ctx initiator;
    struct ccsds_sdls_ep_verify_command command = {.key_count = 1u};
    uint8_t command_wire[CCSDS_SDLS_EP_VERIFY_COMMAND_PDU_MAX];
    uint8_t reply[CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    size_t command_len =
        CCSDS_SDLS_EP_HEADER_LEN + CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN;
    size_t reply_len =
        CCSDS_SDLS_EP_HEADER_LEN + CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN;

    ccsds_sdls_init(&recipient, NULL, 0u, &good_init, 1u);
    ccsds_sdls_init(&initiator, NULL, 0u, &wrong_init, 1u);
    command.entries[0].key_id = 4u;
    memset(command.entries[0].challenge, 0x5a,
           sizeof(command.entries[0].challenge));
    ccsds_sdls_ep_verify_command_encode(&command, command_wire,
                                        sizeof(command_wire));
    zassert_ok(ccsds_sdls_ep_process_key_verification(&recipient, command_wire,
                                                      command_len, workspace,
                                                      reply, sizeof(reply)));
    zassert_equal(ccsds_sdls_ep_check_key_verification(&initiator, command_wire,
                                                       command_len, reply,
                                                       reply_len, workspace),
                  CCSDS_SDLS_ERR_AUTHENTICATION);
    initiator.keys[4].psa_key_id = good;
    reply[reply_len - 1u] ^= 1u;
    zassert_equal(ccsds_sdls_ep_check_key_verification(&initiator, command_wire,
                                                       command_len, reply,
                                                       reply_len, workspace),
                  CCSDS_SDLS_ERR_AUTHENTICATION);
    assert_zero(scratch, sizeof(scratch));
    zassert_equal(psa_destroy_key(good), PSA_SUCCESS);
    zassert_equal(psa_destroy_key(wrong), PSA_SUCCESS);
}

ZTEST(sdls_ep_verification,
      test_failed_recipient_verification_preserves_state_and_output)
{
    psa_key_id_t key = import_aes_key(0x31u, 32u, PSA_ALG_GCM);
    struct ccsds_sdls_key_init key_init = {
        .psa_key_id = key, .key_id = 4u, .state = CCSDS_SDLS_KEY_DEACTIVATED};
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_verify_command command = {.key_count = 1u};
    uint8_t command_wire[CCSDS_SDLS_EP_VERIFY_COMMAND_PDU_MAX];
    uint8_t reply[CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX];
    uint8_t scratch[CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX];
    struct ccsds_sdls_workspace workspace = {scratch, sizeof(scratch)};
    uint64_t original_iv;
    uint32_t original_arsn;

    ccsds_sdls_init(&ctx, NULL, 0u, &key_init, 1u);
    ctx.tx_iv = UINT64_C(0x0123456789abcdef);
    ctx.keys[4].tx_arsn = 42u;
    original_iv = ctx.tx_iv;
    original_arsn = ctx.keys[4].tx_arsn;
    command.entries[0].key_id = 4u;
    memset(command.entries[0].challenge, 0x44,
           sizeof(command.entries[0].challenge));
    ccsds_sdls_ep_verify_command_encode(&command, command_wire,
                                        sizeof(command_wire));
    memset(reply, 0xa5, sizeof(reply));
    memset(scratch, 0x5a, sizeof(scratch));

    zassert_equal(
        ccsds_sdls_ep_process_key_verification(
            &ctx, command_wire,
            CCSDS_SDLS_EP_HEADER_LEN + CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN,
            workspace, reply, sizeof(reply)),
        CCSDS_SDLS_ERR_KEY_STATE);
    zassert_equal(ctx.tx_iv, original_iv);
    zassert_equal(ctx.keys[4].tx_arsn, original_arsn);
    zassert_equal(ctx.keys[4].state, CCSDS_SDLS_KEY_DEACTIVATED);
    zassert_mem_equal(
        reply, (uint8_t[sizeof(reply)]){[0 ... sizeof(reply) - 1] = 0xa5},
        sizeof(reply));
    assert_zero(scratch, sizeof(scratch));
    zassert_equal(psa_destroy_key(key), PSA_SUCCESS);
}

static void *sdls_ep_setup(void)
{
    zassert_equal(psa_crypto_init(), PSA_SUCCESS);
    import_calls = 0;
    fail_import_call = -1;
    destroy_calls = 0;
    last_destroyed = PSA_KEY_ID_NULL;
    return NULL;
}

ZTEST_SUITE(sdls_ep_codec, NULL, sdls_ep_setup, NULL, NULL, NULL);
ZTEST_SUITE(sdls_ep_otar, NULL, sdls_ep_setup, NULL, NULL, NULL);
ZTEST_SUITE(sdls_ep_lifecycle, NULL, sdls_ep_setup, NULL, NULL, NULL);
ZTEST_SUITE(sdls_ep_inventory, NULL, sdls_ep_setup, NULL, NULL, NULL);
ZTEST_SUITE(sdls_ep_rollover, NULL, sdls_ep_setup, NULL, NULL, NULL);
ZTEST_SUITE(sdls_ep_verification, NULL, sdls_ep_setup, NULL, NULL, NULL);
