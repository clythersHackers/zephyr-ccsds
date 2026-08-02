#include <string.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include <ccsds/ccsds_sdls.h>

static void init_empty(struct ccsds_sdls_ctx *ctx)
{
    ccsds_sdls_init(ctx, NULL, 0u, NULL, 0u);
}

static int process(struct ccsds_sdls_ctx *ctx, const uint8_t *command,
                   size_t command_len, uint8_t *reply, size_t reply_capacity,
                   size_t *reply_len)
{
    return ccsds_sdls_ep_process_pdu(
        ctx, command, command_len, (struct ccsds_sdls_workspace){0}, reply,
        reply_capacity, reply_len);
}

static int self_test_ok(void *user_data, uint8_t *result)
{
    int *calls = user_data;

    (*calls)++;
    *result = CCSDS_SDLS_SELF_TEST_OK;
    return 0;
}

static int self_test_failed(void *user_data, uint8_t *result)
{
    ARG_UNUSED(user_data);
    *result = CCSDS_SDLS_SELF_TEST_NOT_OK;
    return 0;
}

static int self_test_unsupported(void *user_data, uint8_t *result)
{
    ARG_UNUSED(user_data);
    ARG_UNUSED(result);
    return CCSDS_SDLS_ERR_UNSUPPORTED;
}

static int self_test_invalid(void *user_data, uint8_t *result)
{
    ARG_UNUSED(user_data);
    *result = 1u;
    return 0;
}

ZTEST(sdls_monitoring, test_exact_monitoring_vectors)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_log_status_reply status;
    uint8_t command[CCSDS_SDLS_EP_HEADER_LEN];
    uint8_t reply[CCSDS_SDLS_EP_DUMP_LOG_PDU_MAX];
    size_t reply_len;
    static const uint8_t tags[] = {0x31u, 0x32u, 0x33u, 0x34u, 0x35u};
    uint8_t expected_command[] = {0u, 0u, 0u};
    static const uint8_t alarm[] = {0x37u, 0u, 0u};
    static const uint8_t ping_reply[] = {0xb1u, 0u, 0u};
    static const uint8_t empty_dump[] = {0xb3u, 0u, 0u};
    static const uint8_t empty_status[] = {
        0xb2u, 0u, 0x20u, 0u, 0u, 0u,
        CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY};

    init_empty(&ctx);
    for (size_t i = 0u; i < ARRAY_SIZE(tags); i++) {
        ccsds_sdls_ep_monitoring_command_encode(
            (enum ccsds_sdls_ep_monitoring_procedure)(i + 1u), command,
            sizeof(command));
        expected_command[0] = tags[i];
        zassert_mem_equal(command, expected_command, sizeof(expected_command));
    }
    ccsds_sdls_ep_alarm_flag_reset_encode(command, sizeof(command));
    zassert_mem_equal(command, alarm, sizeof(alarm));

    ccsds_sdls_ep_monitoring_command_encode(CCSDS_SDLS_EP_PING, command,
                                             sizeof(command));
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(reply_len, 3u);
    zassert_mem_equal(reply, ping_reply, sizeof(ping_reply));

    ccsds_sdls_ep_monitoring_command_encode(CCSDS_SDLS_EP_LOG_STATUS, command,
                                             sizeof(command));
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_mem_equal(reply, empty_status, sizeof(empty_status));
    zassert_ok(ccsds_sdls_ep_log_status_reply_decode(
        reply, reply_len, CCSDS_SDLS_EP_LOG_STATUS, &status));
    zassert_equal(status.retained_events, 0u);
    zassert_equal(status.remaining_slots,
                  CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY);

    ccsds_sdls_ep_monitoring_command_encode(CCSDS_SDLS_EP_ERASE_LOG, command,
                                             sizeof(command));
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(reply[0], 0xb4u);
    zassert_equal(sys_get_be16(reply + 1u), 32u);

    ccsds_sdls_ep_monitoring_command_encode(CCSDS_SDLS_EP_DUMP_LOG, command,
                                             sizeof(command));
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(reply_len, 3u);
    zassert_mem_equal(reply, empty_dump, sizeof(empty_dump));
}

ZTEST(sdls_monitoring, test_ring_wrap_dump_order_and_saturation)
{
    struct ccsds_sdls_ctx ctx;
    uint8_t dump[CCSDS_SDLS_EP_DUMP_LOG_PDU_MAX];
    size_t dump_len;
    size_t insertions = CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY * 3u + 2u;

    init_empty(&ctx);
    for (size_t i = 0u; i < insertions; i++) {
        ccsds_sdls_event_record(&ctx, (uint8_t)(0x40u + i),
                                CCSDS_SDLS_EVENT_KEY_STATE,
                                (uint16_t)(0x100u + i), (uint32_t)(0x1000u + i));
    }
    zassert_equal(ctx.event_count, CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY);
    zassert_equal(ctx.event_overwrites,
                  insertions - CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY);
    zassert_ok(ccsds_sdls_ep_dump_log_reply_encode(&ctx, dump, sizeof(dump),
                                                    &dump_len));
    zassert_equal(dump[0], 0xb3u);
    zassert_equal(sys_get_be16(dump + 1u),
                  CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY *
                      CCSDS_SDLS_EVENT_WIRE_LEN * 8u);
    for (size_t i = 0u; i < CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY; i++) {
        size_t source = insertions - CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY + i;
        size_t offset = CCSDS_SDLS_EP_HEADER_LEN +
                        i * CCSDS_SDLS_EVENT_WIRE_LEN;

        zassert_equal(dump[offset], (uint8_t)(0x40u + source));
        zassert_equal(sys_get_be16(dump + offset + 1u),
                      CCSDS_SDLS_EVENT_VALUE_LEN);
        zassert_equal(dump[offset + 3u], CCSDS_SDLS_EVENT_KEY_STATE);
        zassert_equal(sys_get_be16(dump + offset + 4u),
                      (uint16_t)(0x100u + source));
        zassert_equal(sys_get_be32(dump + offset + 6u),
                      (uint32_t)(0x1000u + source));
    }
    for (size_t i = 0u; i < UINT8_MAX; i++) {
        ccsds_sdls_event_record(&ctx, 1u, CCSDS_SDLS_EVENT_FORMAT, 0u, 0u);
    }
    zassert_equal(ctx.event_overwrites, UINT8_MAX);
}

ZTEST(sdls_monitoring, test_partial_and_full_log_status)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_log_status_reply status;
    uint8_t command[CCSDS_SDLS_EP_HEADER_LEN];
    uint8_t reply[CCSDS_SDLS_EP_HEADER_LEN + 4u];
    size_t reply_len;

    init_empty(&ctx);
    ccsds_sdls_ep_monitoring_command_encode(CCSDS_SDLS_EP_LOG_STATUS, command,
                                             sizeof(command));
    ccsds_sdls_event_record(&ctx, 1u, CCSDS_SDLS_EVENT_FORMAT, 0u, 0u);
    ccsds_sdls_event_record(&ctx, 2u, CCSDS_SDLS_EVENT_KEY_ID, 0u, 0u);
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_ok(ccsds_sdls_ep_log_status_reply_decode(
        reply, reply_len, CCSDS_SDLS_EP_LOG_STATUS, &status));
    zassert_equal(status.retained_events, 2u);
    zassert_equal(status.remaining_slots,
                  CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY - 2u);

    while (ctx.event_count < CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY) {
        ccsds_sdls_event_record(&ctx, 3u, CCSDS_SDLS_EVENT_SA_STATE, 0u, 0u);
    }
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_ok(ccsds_sdls_ep_log_status_reply_decode(
        reply, reply_len, CCSDS_SDLS_EP_LOG_STATUS, &status));
    zassert_equal(status.retained_events,
                  CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY);
    zassert_equal(status.remaining_slots, 0u);
}

ZTEST(sdls_monitoring, test_dump_capacity_and_decoder_outputs_are_atomic)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_ep_log_status_reply decoded = {0xaaaau, 0xbbbbu};
    uint8_t output[CCSDS_SDLS_EVENT_WIRE_LEN + 2u];
    size_t output_len = 99u;
    static const uint8_t bad_status[] = {0xb2u, 0u, 0x18u, 0u, 1u, 0u};

    init_empty(&ctx);
    ccsds_sdls_event_record(&ctx, 0x31u, CCSDS_SDLS_EVENT_FORMAT, 1u, 2u);
    memset(output, 0xa5, sizeof(output));
    zassert_equal(ccsds_sdls_ep_dump_log_reply_encode(
                      &ctx, output, sizeof(output), &output_len),
                  CCSDS_SDLS_ERR_CAPACITY);
    zassert_mem_equal(output,
                      (uint8_t[sizeof(output)]){
                          [0 ... sizeof(output) - 1] = 0xa5},
                      sizeof(output));
    zassert_equal(output_len, 99u);
    zassert_equal(ccsds_sdls_ep_log_status_reply_decode(
                      bad_status, sizeof(bad_status),
                      CCSDS_SDLS_EP_LOG_STATUS, &decoded),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(decoded.retained_events, 0xaaaau);
    zassert_equal(decoded.remaining_slots, 0xbbbbu);
}

ZTEST(sdls_monitoring, test_erase_is_atomic_and_preserves_unrelated_state)
{
    struct ccsds_sdls_ctx ctx;
    uint8_t command[3];
    uint8_t reply[7];
    uint8_t too_small[6] = {0};
    size_t reply_len = 55u;

    init_empty(&ctx);
    ctx.fsr = (struct ccsds_sdls_fsr){.alarm = true,
                                      .bad_mac = true,
                                      .last_spi = 0x1234u,
                                      .last_arsn_lsb = 0x56u};
    ctx.tx_iv = 0x123456789abcdef0u;
    ctx.fsr_next = true;
    ccsds_sdls_event_record(&ctx, 1u, CCSDS_SDLS_EVENT_FORMAT, 2u, 3u);
    ccsds_sdls_ep_monitoring_command_encode(CCSDS_SDLS_EP_ERASE_LOG, command,
                                             sizeof(command));
    zassert_equal(process(&ctx, command, sizeof(command), too_small,
                          sizeof(too_small), &reply_len),
                  CCSDS_SDLS_ERR_CAPACITY);
    zassert_equal(ctx.event_count, 1u);
    zassert_equal(reply_len, 55u);

    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(ctx.event_count, 0u);
    zassert_equal(ctx.event_read_index, 0u);
    zassert_equal(ctx.event_write_index, 0u);
    zassert_equal(ctx.event_overwrites, 0u);
    zassert_mem_equal(ctx.events, (uint8_t[sizeof(ctx.events)]){0},
                      sizeof(ctx.events));
    zassert_true(ctx.fsr.alarm);
    zassert_true(ctx.fsr.bad_mac);
    zassert_equal(ctx.fsr.last_spi, 0x1234u);
    zassert_equal(ctx.tx_iv, 0x123456789abcdef0u);
    zassert_true(ctx.fsr_next);
}

ZTEST(sdls_monitoring, test_alarm_reset_preserves_event_ring)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_event before;
    uint8_t command[CCSDS_SDLS_EP_HEADER_LEN];
    size_t reply_len = 1u;

    init_empty(&ctx);
    ctx.fsr.alarm = true;
    ctx.fsr.bad_sequence = true;
    ctx.fsr.bad_mac = true;
    ctx.fsr.bad_sa = true;
    ctx.fsr.last_spi = 0x1234u;
    ctx.fsr.last_arsn_lsb = 0x56u;
    ccsds_sdls_event_record(&ctx, 0x31u, CCSDS_SDLS_EVENT_FORMAT, 1u, 2u);
    before = ctx.events[0];
    ccsds_sdls_ep_alarm_flag_reset_encode(command, sizeof(command));
    zassert_ok(process(&ctx, command, sizeof(command), NULL, 0u, &reply_len));
    zassert_false(ctx.fsr.alarm);
    zassert_false(ctx.fsr.bad_sequence);
    zassert_false(ctx.fsr.bad_mac);
    zassert_false(ctx.fsr.bad_sa);
    zassert_equal(ctx.fsr.last_spi, 0x1234u);
    zassert_equal(ctx.fsr.last_arsn_lsb, 0x56u);
    zassert_equal(ctx.event_count, 1u);
    zassert_mem_equal(&ctx.events[0], &before, sizeof(before));
    zassert_equal(reply_len, 0u);
}

ZTEST(sdls_monitoring, test_self_test_contract)
{
    struct ccsds_sdls_ctx ctx;
    uint8_t command[3];
    uint8_t reply[4];
    uint8_t result = 0xa5u;
    size_t reply_len = 77u;
    int calls = 0;
    static const uint8_t missing_reply[] = {0xb5u, 0u, 8u, 0x80u};
    static const uint8_t unchanged[] = {0xa5u, 0xa5u, 0xa5u, 0xa5u};

    init_empty(&ctx);
    ccsds_sdls_ep_monitoring_command_encode(CCSDS_SDLS_EP_SELF_TEST, command,
                                             sizeof(command));
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_mem_equal(reply, missing_reply, sizeof(missing_reply));
    zassert_equal(ctx.event_count, 1u);

    ccsds_sdls_set_self_test(&ctx, self_test_ok, &calls);
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(calls, 1);
    zassert_equal(ctx.event_count, 1u);
    zassert_ok(ccsds_sdls_ep_self_test_reply_decode(reply, reply_len, &result));
    zassert_equal(result, CCSDS_SDLS_SELF_TEST_OK);

    ccsds_sdls_set_self_test(&ctx, self_test_failed, NULL);
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(reply[3], CCSDS_SDLS_SELF_TEST_NOT_OK);
    zassert_equal(ctx.event_count, 2u);

    ccsds_sdls_set_self_test(&ctx, self_test_unsupported, NULL);
    zassert_ok(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(reply[3], CCSDS_SDLS_SELF_TEST_NOT_OK);

    ccsds_sdls_set_self_test(&ctx, self_test_invalid, NULL);
    memset(reply, 0xa5, sizeof(reply));
    reply_len = 77u;
    zassert_equal(process(&ctx, command, sizeof(command), reply, sizeof(reply),
                          &reply_len),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_mem_equal(reply, unchanged, sizeof(unchanged));
    zassert_equal(reply_len, 77u);
    zassert_equal(result, CCSDS_SDLS_SELF_TEST_OK);
}

ZTEST(sdls_monitoring, test_ep_failure_provenance_and_stale_metadata)
{
    struct ccsds_sdls_ctx ctx;
    uint8_t bad_ping[] = {0x31u, 0u, 8u, 0xaau};
    uint8_t ping[] = {0x31u, 0u, 0u};
    uint8_t reply[3];
    size_t reply_len = 0u;

    init_empty(&ctx);
    ctx.authenticated_rx_valid = true;
    ctx.authenticated_rx_spi = 0x1234u;
    ctx.authenticated_rx_arsn = 0x89abcdefu;
    zassert_equal(process(&ctx, bad_ping, sizeof(bad_ping), reply,
                          sizeof(reply), &reply_len),
                  CCSDS_SDLS_ERR_FORMAT);
    zassert_equal(ctx.event_count, 1u);
    zassert_equal(ctx.events[0].pdu_or_event_tag, 0x31u);
    zassert_equal(ctx.events[0].spi, 0x1234u);
    zassert_equal(ctx.events[0].arsn, 0x89abcdefu);
    zassert_false(ctx.authenticated_rx_valid);
    zassert_equal(ctx.authenticated_rx_spi, 0u);
    zassert_equal(ctx.authenticated_rx_arsn, 0u);

    zassert_ok(process(&ctx, ping, sizeof(ping), reply, sizeof(reply),
                       &reply_len));
    zassert_equal(ctx.event_count, 1u);
}

ZTEST_SUITE(sdls_monitoring, NULL, NULL, NULL, NULL, NULL);
