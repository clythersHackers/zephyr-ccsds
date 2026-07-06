#include <zephyr/ztest.h>

#include <string.h>

#include "ccsds/ccsds_cfdp_entity.h"

static int test_send_pdu(void *user, uint64_t dest_entity_id,
                         const uint8_t *pdu, size_t pdu_len)
{
    ARG_UNUSED(user);
    ARG_UNUSED(dest_entity_id);
    ARG_UNUSED(pdu);
    ARG_UNUSED(pdu_len);

    return 0;
}

static ccsds_cfdp_entity_config_t base_config(void)
{
    return (ccsds_cfdp_entity_config_t){
        .local_entity_id = 0x12u,
        .remote_entity_id = 0x34u,
        .entity_id_len = 1u,
        .transaction_sequence_number_len = 1u,
        .initial_transaction_sequence_number = 7u,
    };
}

static ccsds_cfdp_ut_ops_t base_ut(void)
{
    return (ccsds_cfdp_ut_ops_t){
        .user = NULL,
        .send_pdu = test_send_pdu,
        .now_ms = NULL,
    };
}

static void init_entity(ccsds_cfdp_entity_t *entity)
{
    const ccsds_cfdp_entity_config_t config = base_config();
    const ccsds_cfdp_ut_ops_t ut = base_ut();

    memset(entity, 0xa5, sizeof(*entity));
    zassert_equal(ccsds_cfdp_entity_init(entity, &config, &ut),
                  CCSDS_CFDP_STATUS_OK);
}

static void make_incoming_pdu(uint64_t source_entity_id,
                              uint64_t transaction_sequence_number,
                              uint64_t destination_entity_id, uint8_t *buf,
                              size_t cap, size_t *len)
{
    const ccsds_cfdp_pdu_header_t header = {
        .version = CCSDS_CFDP_VERSION_1,
        .pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
        .direction = CCSDS_CFDP_DIRECTION_TOWARD_RECEIVER,
        .transmission_mode = CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED,
        .crc_flag = CCSDS_CFDP_CRC_NOT_PRESENT,
        .file_size_mode = CCSDS_CFDP_FILE_SIZE_SMALL,
        .pdu_data_field_len = 0u,
        .segmentation_control =
            CCSDS_CFDP_SEGMENTATION_RECORD_BOUNDARIES_NOT_PRESERVED,
        .segment_metadata_present = false,
        .entity_id_len = 1u,
        .transaction_sequence_number_len = 1u,
        .source_entity_id = source_entity_id,
        .transaction_sequence_number = transaction_sequence_number,
        .destination_entity_id = destination_entity_id,
    };

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
}

ZTEST(ccsds_cfdp_entity, test_init_sets_fixed_config_and_empty_slots)
{
    ccsds_cfdp_entity_t entity;
    const ccsds_cfdp_entity_config_t config = base_config();
    const ccsds_cfdp_ut_ops_t ut = base_ut();

    zassert_equal(ccsds_cfdp_entity_init(&entity, &config, &ut),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(entity.local_entity_id, config.local_entity_id);
    zassert_equal(entity.remote_entity_id, config.remote_entity_id);
    zassert_equal(entity.entity_id_len, config.entity_id_len);
    zassert_equal(entity.transaction_sequence_number_len,
                  config.transaction_sequence_number_len);
    zassert_equal(entity.next_transaction_sequence_number,
                  config.initial_transaction_sequence_number);
    zassert_equal(entity.ut.send_pdu, test_send_pdu);
    zassert_false(entity.sender.active);
    zassert_false(entity.receiver.active);
}

ZTEST(ccsds_cfdp_entity, test_init_rejects_invalid_config)
{
    ccsds_cfdp_entity_t entity;
    ccsds_cfdp_entity_config_t config = base_config();
    ccsds_cfdp_ut_ops_t ut = base_ut();

    config.entity_id_len = 0u;
    zassert_equal(ccsds_cfdp_entity_init(&entity, &config, &ut),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);

    config = base_config();
    config.initial_transaction_sequence_number = 0x100u;
    zassert_equal(ccsds_cfdp_entity_init(&entity, &config, &ut),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);

    config = base_config();
    ut.send_pdu = NULL;
    zassert_equal(ccsds_cfdp_entity_init(&entity, &config, &ut),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
}

ZTEST(ccsds_cfdp_entity, test_sender_transaction_ids_allocate_and_increment)
{
    ccsds_cfdp_entity_t entity;
    ccsds_cfdp_transaction_id_t id;

    init_entity(&entity);

    zassert_equal(ccsds_cfdp_entity_create_sender_transaction(&entity, &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(id.source_entity_id, 0x12u);
    zassert_equal(id.transaction_sequence_number, 7u);
    zassert_true(entity.sender.active);

    ccsds_cfdp_entity_release_sender_transaction(&entity);

    zassert_equal(ccsds_cfdp_entity_create_sender_transaction(&entity, &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(id.source_entity_id, 0x12u);
    zassert_equal(id.transaction_sequence_number, 8u);
}

ZTEST(ccsds_cfdp_entity, test_rejects_second_sender_transaction)
{
    ccsds_cfdp_entity_t entity;
    ccsds_cfdp_transaction_id_t id;

    init_entity(&entity);

    zassert_equal(ccsds_cfdp_entity_create_sender_transaction(&entity, &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_create_sender_transaction(&entity, &id),
                  CCSDS_CFDP_STATUS_TRANSACTION_BUSY);
}

ZTEST(ccsds_cfdp_entity, test_incoming_pdu_creates_and_matches_receiver)
{
    ccsds_cfdp_entity_t entity;
    ccsds_cfdp_transaction_id_t id;
    uint8_t pdu[16];
    size_t pdu_len;

    init_entity(&entity);
    make_incoming_pdu(0x34u, 0x22u, 0x12u, pdu, sizeof(pdu), &pdu_len);

    zassert_equal(ccsds_cfdp_entity_match_or_create_receiver_transaction(
                      &entity, pdu, pdu_len, &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_true(entity.receiver.active);
    zassert_equal(id.source_entity_id, 0x34u);
    zassert_equal(id.transaction_sequence_number, 0x22u);

    memset(&id, 0, sizeof(id));
    zassert_equal(ccsds_cfdp_entity_match_or_create_receiver_transaction(
                      &entity, pdu, pdu_len, &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(id.source_entity_id, 0x34u);
    zassert_equal(id.transaction_sequence_number, 0x22u);
}

ZTEST(ccsds_cfdp_entity, test_rejects_second_receiver_transaction)
{
    ccsds_cfdp_entity_t entity;
    ccsds_cfdp_transaction_id_t id;
    uint8_t first_pdu[16];
    uint8_t second_pdu[16];
    size_t first_pdu_len;
    size_t second_pdu_len;

    init_entity(&entity);
    make_incoming_pdu(0x34u, 0x22u, 0x12u, first_pdu, sizeof(first_pdu),
                      &first_pdu_len);
    make_incoming_pdu(0x34u, 0x23u, 0x12u, second_pdu, sizeof(second_pdu),
                      &second_pdu_len);

    zassert_equal(ccsds_cfdp_entity_match_or_create_receiver_transaction(
                      &entity, first_pdu, first_pdu_len, &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_match_or_create_receiver_transaction(
                      &entity, second_pdu, second_pdu_len, &id),
                  CCSDS_CFDP_STATUS_TRANSACTION_BUSY);
}

ZTEST(ccsds_cfdp_entity, test_receiver_rejects_unexpected_peer_or_destination)
{
    ccsds_cfdp_entity_t entity;
    ccsds_cfdp_transaction_id_t id;
    uint8_t pdu[16];
    size_t pdu_len;

    init_entity(&entity);

    make_incoming_pdu(0x35u, 0x22u, 0x12u, pdu, sizeof(pdu), &pdu_len);
    zassert_equal(ccsds_cfdp_entity_match_or_create_receiver_transaction(
                      &entity, pdu, pdu_len, &id),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);

    make_incoming_pdu(0x34u, 0x22u, 0x13u, pdu, sizeof(pdu), &pdu_len);
    zassert_equal(ccsds_cfdp_entity_match_or_create_receiver_transaction(
                      &entity, pdu, pdu_len, &id),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST_SUITE(ccsds_cfdp_entity, NULL, NULL, NULL, NULL, NULL);
