#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include <ccsds/ccsds_sdls.h>

static psa_key_id_t sa_management_keys[4];

static void transition_to_expired(struct ccsds_sdls_ctx *ctx, uint16_t spi);

static psa_key_id_t import_key(uint8_t seed)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t material[CCSDS_SDLS_EP_KEY_LEN];
    psa_key_id_t key = PSA_KEY_ID_NULL;

    for (size_t i = 0u; i < sizeof(material); i++) {
        material[i] = seed + (uint8_t)i;
    }
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, CCSDS_SDLS_AES_KEY_BITS);
    zassert_equal(psa_import_key(&attributes, material, sizeof(material), &key),
                  PSA_SUCCESS);
    memset(material, 0, sizeof(material));
    psa_reset_key_attributes(&attributes);
    return key;
}

static void init_sa_management_ctx(struct ccsds_sdls_ctx *ctx)
{
    struct ccsds_sdls_key_init keys[] = {
        {.psa_key_id = sa_management_keys[0],
         .key_id = 4u,
         .state = CCSDS_SDLS_KEY_ACTIVE},
        {.psa_key_id = sa_management_keys[1],
         .key_id = 5u,
         .state = CCSDS_SDLS_KEY_ACTIVE},
        {.psa_key_id = sa_management_keys[2],
         .key_id = 6u,
         .state = CCSDS_SDLS_KEY_ACTIVE},
        {.psa_key_id = sa_management_keys[3],
         .key_id = 7u,
         .state = CCSDS_SDLS_KEY_ACTIVE},
    };
    struct ccsds_sdls_sa_init sas[] = {
        {.spi = 1u,
         .key_id = 4u,
         .role = CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
         .mode = CCSDS_SDLS_MODE_GMAC,
         .state = CCSDS_SDLS_SA_OPERATIONAL,
         .has_key = true,
         .rx_arsn_initialized = true,
         .rx_arsn = 10u},
        {.spi = 2u,
         .key_id = 6u,
         .role = CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
         .mode = CCSDS_SDLS_MODE_GCM,
         .state = CCSDS_SDLS_SA_OPERATIONAL,
         .has_key = true},
        {.spi = 3u,
         .role = CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
         .mode = CCSDS_SDLS_MODE_CLEAR,
         .state = CCSDS_SDLS_SA_STOPPED,
         .has_key = false},
    };

    ccsds_sdls_init(ctx, sas, ARRAY_SIZE(sas), keys, ARRAY_SIZE(keys));
}

ZTEST(sdls_sa_management, test_clear_sa_requires_different_authenticated_sa)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_start_sa start = {.spi = 3u};
    uint8_t wire[CCSDS_SDLS_EP_START_SA_PDU_MAX];
    size_t reply_len = 0u;

    init_sa_management_ctx(&ctx);
    ccsds_sdls_ep_start_sa_encode(&start, wire, sizeof(wire));
    zassert_equal(ccsds_sdls_ep_process_pdu(
                      &ctx, wire, CCSDS_SDLS_EP_HEADER_LEN + 2u,
                      (struct ccsds_sdls_workspace){0}, NULL, 0u, &reply_len),
                  CCSDS_SDLS_ERR_AUTHENTICATION);

    ctx.authenticated_rx_valid = true;
    ctx.authenticated_rx_spi = 3u;
    zassert_equal(ccsds_sdls_ep_process_pdu(
                      &ctx, wire, CCSDS_SDLS_EP_HEADER_LEN + 2u,
                      (struct ccsds_sdls_workspace){0}, NULL, 0u, &reply_len),
                  CCSDS_SDLS_ERR_AUTHENTICATION);

    ctx.authenticated_rx_valid = true;
    ctx.authenticated_rx_spi = 1u;
    zassert_ok(ccsds_sdls_ep_process_pdu(
        &ctx, wire, CCSDS_SDLS_EP_HEADER_LEN + 2u,
        (struct ccsds_sdls_workspace){0}, NULL, 0u, &reply_len));
    zassert_equal(ctx.sas[2].state, CCSDS_SDLS_SA_OPERATIONAL);
}

ZTEST(sdls_sa_management,
      test_preprovisioned_startup_key_can_start_but_not_rekey)
{
    const struct ccsds_sdls_key_init key = {
        .psa_key_id = sa_management_keys[0],
        .key_id = 1u,
        .state = CCSDS_SDLS_KEY_ACTIVE,
    };
    const struct ccsds_sdls_sa_init sa = {
        .spi = 1u,
        .key_id = 1u,
        .role = CCSDS_SDLS_SA_EP_REPLY_TX,
        .mode = CCSDS_SDLS_MODE_GCM,
        .state = CCSDS_SDLS_SA_STOPPED,
        .has_key = true,
    };
    struct ccsds_sdls_ep_start_sa start = {.spi = 1u};
    struct ccsds_sdls_ep_rekey_sa rekey = {
        .spi = 1u,
        .key_id = 1u,
    };
    struct ccsds_sdls_ctx ctx;
    uint8_t wire[CCSDS_SDLS_EP_SA_REKEY_PDU_MAX];

    ccsds_sdls_init(&ctx, &sa, 1u, &key, 1u);
    ccsds_sdls_ep_start_sa_encode(&start, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_start_sa(
        &ctx, wire, CCSDS_SDLS_EP_HEADER_LEN + 2u));
    transition_to_expired(&ctx, 1u);
    ccsds_sdls_ep_rekey_sa_encode(&rekey, wire, sizeof(wire));
    zassert_equal(ccsds_sdls_ep_process_rekey_sa(
                      &ctx, wire, CCSDS_SDLS_EP_HEADER_LEN + 4u),
                  CCSDS_SDLS_ERR_KEY);
}

ZTEST(sdls_sa_management, test_exact_sa_management_vectors)
{
    struct ccsds_sdls_ep_start_sa start = {.spi = 2u};
    struct ccsds_sdls_ep_start_sa decoded_start;
    struct ccsds_sdls_ep_sa_command simple = {.spi = 2u};
    struct ccsds_sdls_ep_rekey_sa rekey = {
        .spi = 1u, .key_id = 5u, .rx_arsn = 0x12345678u, .has_rx_arsn = true};
    struct ccsds_sdls_ep_rekey_sa decoded_rekey;
    struct ccsds_sdls_ep_set_arsn set = {.spi = 1u, .arsn = 0x89abcdefu};
    struct ccsds_sdls_ep_set_arsn decoded_set;
    struct ccsds_sdls_ep_set_arsn_window window = {.spi = 1u, .window = 8u};
    struct ccsds_sdls_ep_set_arsn_window decoded_window;
    uint8_t wire[CCSDS_SDLS_EP_START_SA_PDU_MAX];
    static const uint8_t start_zero[] = {0x1bu, 0x00u, 0x10u, 0x00u, 0x02u};
    static const uint8_t stop[] = {0x1eu, 0x00u, 0x10u, 0x00u, 0x02u};
    static const uint8_t expire[] = {0x19u, 0x00u, 0x10u, 0x00u, 0x02u};
    static const uint8_t expected_rekey[] = {0x16u, 0x00u, 0x40u, 0x00u,
                                             0x01u, 0x00u, 0x05u, 0x12u,
                                             0x34u, 0x56u, 0x78u};
    static const uint8_t expected_set[] = {0x1au, 0x00u, 0x30u, 0x00u, 0x01u,
                                           0x89u, 0xabu, 0xcdu, 0xefu};
    static const uint8_t expected_window[] = {0x15u, 0x00u, 0x30u, 0x00u, 0x01u,
                                              0x00u, 0x00u, 0x00u, 0x08u};
    static const uint8_t alarm[] = {0x37u, 0x00u, 0x00u};

    ccsds_sdls_ep_start_sa_encode(&start, wire, sizeof(wire));
    zassert_mem_equal(wire, start_zero, sizeof(start_zero));
    zassert_ok(ccsds_sdls_ep_start_sa_decode(wire, sizeof(start_zero),
                                             &decoded_start));
    zassert_equal(decoded_start.spi, 2u);
    zassert_equal(decoded_start.association_count, 0u);

    ccsds_sdls_ep_sa_command_encode(CCSDS_SDLS_EP_STOP_SA, &simple, wire,
                                    sizeof(wire));
    zassert_mem_equal(wire, stop, sizeof(stop));
    ccsds_sdls_ep_sa_command_encode(CCSDS_SDLS_EP_EXPIRE_SA, &simple, wire,
                                    sizeof(wire));
    zassert_mem_equal(wire, expire, sizeof(expire));

    ccsds_sdls_ep_rekey_sa_encode(&rekey, wire, sizeof(wire));
    zassert_mem_equal(wire, expected_rekey, sizeof(expected_rekey));
    zassert_ok(ccsds_sdls_ep_rekey_sa_decode(wire, sizeof(expected_rekey),
                                             &decoded_rekey));
    zassert_equal(decoded_rekey.rx_arsn, rekey.rx_arsn);

    ccsds_sdls_ep_set_arsn_encode(&set, wire, sizeof(wire));
    zassert_mem_equal(wire, expected_set, sizeof(expected_set));
    zassert_ok(ccsds_sdls_ep_set_arsn_decode(wire, sizeof(expected_set),
                                             &decoded_set));
    zassert_equal(decoded_set.arsn, set.arsn);

    ccsds_sdls_ep_set_arsn_window_encode(&window, wire, sizeof(wire));
    zassert_mem_equal(wire, expected_window, sizeof(expected_window));
    zassert_ok(ccsds_sdls_ep_set_arsn_window_decode(
        wire, sizeof(expected_window), &decoded_window));
    zassert_equal(decoded_window.window, window.window);

    ccsds_sdls_ep_alarm_flag_reset_encode(wire, sizeof(wire));
    zassert_mem_equal(wire, alarm, sizeof(alarm));
}

ZTEST(sdls_sa_management, test_malformed_lengths_nested_unknown_and_trailing)
{
    struct ccsds_sdls_ep_start_sa start;
    struct ccsds_sdls_ep_pdu pdu;
    uint8_t incomplete_assoc[] = {0x1bu, 0x00u, 0x18u, 0x00u, 0x01u, 0xaau};
    uint8_t non_octet[] = {0x1bu, 0x00u, 0x11u, 0x00u, 0x01u};
    uint8_t trailing[] = {0x1bu, 0x00u, 0x10u, 0x00u, 0x01u, 0u};
    uint8_t create[] = {0x11u, 0x00u, 0x10u, 0x00u, 0x01u};
    uint8_t nested[] = {0x1bu, 0x00u, 0x18u, 0x1bu, 0x00u, 0u};

    zassert_equal(ccsds_sdls_ep_start_sa_decode(
                      incomplete_assoc, sizeof(incomplete_assoc), &start),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_ep_pdu_decode(non_octet, sizeof(non_octet), &pdu),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(
        ccsds_sdls_ep_start_sa_decode(trailing, sizeof(trailing), &start),
        CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ccsds_sdls_ep_pdu_decode(create, sizeof(create), &pdu),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_equal(ccsds_sdls_ep_start_sa_decode(nested, sizeof(nested), &start),
                  CCSDS_SDLS_ERR_FORMAT);
}

static void transition_to_expired(struct ccsds_sdls_ctx *ctx, uint16_t spi)
{
    struct ccsds_sdls_ep_sa_command command = {.spi = spi};
    uint8_t wire[CCSDS_SDLS_EP_HEADER_LEN + 2u];

    ccsds_sdls_ep_sa_command_encode(CCSDS_SDLS_EP_STOP_SA, &command, wire,
                                    sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_stop_sa(ctx, wire, sizeof(wire)));
    ccsds_sdls_ep_sa_command_encode(CCSDS_SDLS_EP_EXPIRE_SA, &command, wire,
                                    sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_expire_sa(ctx, wire, sizeof(wire)));
}

ZTEST(sdls_sa_management, test_rekey_tc_and_tm_without_reboot)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_rekey_sa rekey_rx = {
        .spi = 1u, .key_id = 5u, .rx_arsn = 100u, .has_rx_arsn = true};
    struct ccsds_sdls_ep_rekey_sa rekey_tx = {
        .spi = 2u, .key_id = 7u, .has_rx_arsn = false};
    struct ccsds_sdls_ep_start_sa start;
    uint8_t wire[CCSDS_SDLS_EP_SA_REKEY_PDU_MAX];

    init_sa_management_ctx(&ctx);
    ctx.keys[7].tx_arsn = 77u;
    transition_to_expired(&ctx, 1u);
    transition_to_expired(&ctx, 2u);

    ccsds_sdls_ep_rekey_sa_encode(&rekey_rx, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_rekey_sa(&ctx, wire, 11u));
    zassert_equal(ctx.sas[0].key_slot, 5u);
    zassert_equal(ctx.sas[0].rx_arsn, 100u);
    zassert_true(ctx.sas[0].rx_arsn_initialized);

    ccsds_sdls_ep_rekey_sa_encode(&rekey_tx, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_rekey_sa(&ctx, wire, 7u));
    zassert_equal(ctx.sas[1].key_slot, 7u);
    zassert_equal(ctx.keys[7].tx_arsn, 77u);

    start = (struct ccsds_sdls_ep_start_sa){.spi = 1u};
    ccsds_sdls_ep_start_sa_encode(&start, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_start_sa(&ctx, wire, 5u));
    start.spi = 2u;
    ccsds_sdls_ep_start_sa_encode(&start, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_start_sa(&ctx, wire, 5u));
    zassert_equal(ctx.sas[0].state, CCSDS_SDLS_SA_OPERATIONAL);
    zassert_equal(ctx.sas[1].state, CCSDS_SDLS_SA_OPERATIONAL);
}

ZTEST(sdls_sa_management,
      test_failed_rekey_is_atomic_and_create_delete_unsupported)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ctx before;
    struct ccsds_sdls_ep_rekey_sa rekey = {
        .spi = 1u, .key_id = 6u, .rx_arsn = 100u, .has_rx_arsn = true};
    uint8_t wire[CCSDS_SDLS_EP_SA_REKEY_PDU_MAX];
    uint8_t create[] = {0x11u, 0x00u, 0x10u, 0x00u, 0x03u};
    uint8_t delete_sa[] = {0x14u, 0x00u, 0x10u, 0x00u, 0x01u};

    init_sa_management_ctx(&ctx);
    transition_to_expired(&ctx, 1u);
    memcpy(&before, &ctx, sizeof(ctx));
    ccsds_sdls_ep_rekey_sa_encode(&rekey, wire, sizeof(wire));
    zassert_equal(ccsds_sdls_ep_process_rekey_sa(&ctx, wire, 11u),
                  CCSDS_SDLS_ERR_KEY);
    zassert_mem_equal(&ctx, &before, sizeof(ctx));
    zassert_equal(ccsds_sdls_ep_process_start_sa(&ctx, create, sizeof(create)),
                  CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_equal(
        ccsds_sdls_ep_process_expire_sa(&ctx, delete_sa, sizeof(delete_sa)),
        CCSDS_SDLS_ERR_UNSUPPORTED);
    zassert_mem_equal(&ctx, &before, sizeof(ctx));
}

ZTEST(sdls_sa_management, test_arsn_window_read_status_and_alarm_reset)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_set_arsn set = {.spi = 1u, .arsn = 42u};
    struct ccsds_sdls_ep_set_arsn_window window = {.spi = 1u, .window = 3u};
    struct ccsds_sdls_ep_sa_command query = {.spi = 1u};
    struct ccsds_sdls_ep_read_arsn_reply arsn_reply;
    struct ccsds_sdls_ep_sa_status_reply status_reply;
    size_t reply_len = 99u;
    uint8_t wire[16];
    uint8_t reply[CCSDS_SDLS_EP_SA_REPLY_PDU_MAX];

    init_sa_management_ctx(&ctx);
    ccsds_sdls_ep_set_arsn_encode(&set, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_set_arsn(&ctx, wire, 9u));
    ccsds_sdls_ep_set_arsn_window_encode(&window, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_set_arsn_window(&ctx, wire, 9u));
    zassert_equal(ctx.sas[0].rx_window, 3u);

    ccsds_sdls_ep_sa_command_encode(CCSDS_SDLS_EP_READ_ARSN, &query, wire,
                                    sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_read_arsn(&ctx, wire, 5u, reply,
                                               sizeof(reply), &reply_len));
    zassert_equal(reply_len, 9u);
    zassert_ok(
        ccsds_sdls_ep_read_arsn_reply_decode(reply, reply_len, &arsn_reply));
    zassert_equal(arsn_reply.arsn, 42u);

    ccsds_sdls_ep_sa_command_encode(CCSDS_SDLS_EP_SA_STATUS, &query, wire,
                                    sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_sa_status(&ctx, wire, 5u, reply,
                                               sizeof(reply), &reply_len));
    zassert_ok(
        ccsds_sdls_ep_sa_status_reply_decode(reply, reply_len, &status_reply));
    zassert_equal(status_reply.last_procedure, 0x15u);

    ctx.fsr = (struct ccsds_sdls_fsr){.alarm = true,
                                      .bad_sequence = true,
                                      .bad_mac = true,
                                      .bad_sa = true,
                                      .last_spi = 0x1234u,
                                      .last_arsn_lsb = 0x56u};
    ccsds_sdls_ep_alarm_flag_reset_encode(wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_alarm_flag_reset(&ctx, wire, 3u));
    zassert_false(ctx.fsr.alarm);
    zassert_false(ctx.fsr.bad_sequence);
    zassert_false(ctx.fsr.bad_mac);
    zassert_false(ctx.fsr.bad_sa);
    zassert_equal(ctx.fsr.last_spi, 0x1234u);
    zassert_equal(ctx.fsr.last_arsn_lsb, 0x56u);
    zassert_equal(ctx.sas[0].rx_arsn, 42u);
    zassert_equal(ctx.sas[0].rx_window, 3u);
}

ZTEST(sdls_sa_management, test_fsr_exact_encoding)
{
    struct ccsds_sdls_ctx ctx;
    uint8_t fsr[CCSDS_SDLS_FSR_LEN];
    static const uint8_t expected[] = {0x4fu, 0x12u, 0x34u, 0x78u};

    init_sa_management_ctx(&ctx);
    ctx.fsr.alarm = true;
    ctx.fsr.bad_sequence = true;
    ctx.fsr.bad_mac = true;
    ctx.fsr.bad_sa = true;
    ctx.fsr.last_spi = 0x1234u;
    ctx.fsr.last_arsn_lsb = 0x78u;
    ccsds_sdls_fsr_encode(&ctx, fsr);
    zassert_mem_equal(fsr, expected, sizeof(expected));
    zassert_false(ctx.fsr_enabled);
    zassert_false(ctx.fsr_next);
    ccsds_sdls_fsr_set_enabled(&ctx, true);
    zassert_true(ctx.fsr_enabled);
}

ZTEST(sdls_sa_management, test_packet_pdu_does_not_manage_frame_fsr)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_set_arsn set = {.spi = 1u, .arsn = 42u};
    struct ccsds_sdls_workspace unused_workspace = {0};
    size_t reply_len = 77u;
    uint8_t wire[CCSDS_SDLS_EP_HEADER_LEN + 6u];

    init_sa_management_ctx(&ctx);
    ctx.fsr.last_spi = 2u;
    ctx.fsr.last_arsn_lsb = 0x78u;
    ctx.authenticated_rx_spi = 2u;
    ctx.authenticated_rx_valid = true;
    ccsds_sdls_ep_set_arsn_encode(&set, wire, sizeof(wire));
    zassert_ok(ccsds_sdls_ep_process_pdu(&ctx, wire, sizeof(wire),
                                         unused_workspace, NULL, 0u,
                                         &reply_len));
    zassert_equal(ctx.sas[0].rx_arsn, 42u);
    zassert_equal(ctx.fsr.last_spi, 2u);
    zassert_equal(ctx.fsr.last_arsn_lsb, 0x78u);
    zassert_equal(reply_len, 0u);

    set.arsn = 41u;
    ccsds_sdls_ep_set_arsn_encode(&set, wire, sizeof(wire));
    reply_len = 77u;
    zassert_equal(ccsds_sdls_ep_process_pdu(
                      &ctx, wire, sizeof(wire), unused_workspace, NULL, 0u,
                      &reply_len),
                  CCSDS_SDLS_ERR_REPLAY);
    zassert_equal(ctx.sas[0].rx_arsn, 42u);
    zassert_equal(ctx.fsr.last_arsn_lsb, 0x78u);
    zassert_equal(reply_len, 77u);

    set.arsn = 43u;
    ccsds_sdls_ep_set_arsn_encode(&set, wire, sizeof(wire));
    ctx.authenticated_rx_spi = 1u;
    ctx.authenticated_rx_arsn = 99u;
    ctx.authenticated_rx_valid = true;
    zassert_ok(ccsds_sdls_ep_process_pdu(&ctx, wire, sizeof(wire),
                                         unused_workspace, NULL, 0u,
                                         &reply_len));
    zassert_equal(ctx.sas[0].rx_arsn, 43u);
    zassert_equal(ctx.fsr.last_arsn_lsb, 0x78u);
    zassert_false(ctx.authenticated_rx_valid);
}

static void *sa_management_setup(void)
{
    zassert_equal(psa_crypto_init(), PSA_SUCCESS);
    return NULL;
}

static void sa_management_before(void *fixture)
{
    ARG_UNUSED(fixture);
    for (size_t i = 0u; i < ARRAY_SIZE(sa_management_keys); i++) {
        sa_management_keys[i] = import_key((uint8_t)(0x20u * (i + 1u)));
    }
}

static void sa_management_after(void *fixture)
{
    ARG_UNUSED(fixture);
    for (size_t i = 0u; i < ARRAY_SIZE(sa_management_keys); i++) {
        zassert_equal(psa_destroy_key(sa_management_keys[i]), PSA_SUCCESS);
        sa_management_keys[i] = PSA_KEY_ID_NULL;
    }
}

ZTEST_SUITE(sdls_sa_management, NULL, sa_management_setup,
            sa_management_before, sa_management_after, NULL);
