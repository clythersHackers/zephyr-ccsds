#include <zephyr/ztest.h>

#include <string.h>

#include "ccsds/ccsds_cfdp_entity.h"

#define CAPTURE_MAX_PDUS 8u

struct send_capture {
    uint32_t count;
    uint64_t dest_entity_id[CAPTURE_MAX_PDUS];
    uint8_t pdu[CAPTURE_MAX_PDUS][CCSDS_CFDP_MAX_PDU_SIZE];
    size_t pdu_len[CAPTURE_MAX_PDUS];
};

struct memory_filestore {
    const uint8_t *data;
    uint32_t size;
    uint32_t read_count;
    uint32_t close_count;
};

static int test_send_pdu(void *user, uint64_t dest_entity_id,
                         const uint8_t *pdu, size_t pdu_len)
{
    struct send_capture *capture = user;

    if (capture != NULL && capture->count < CAPTURE_MAX_PDUS) {
        capture->dest_entity_id[capture->count] = dest_entity_id;
        memcpy(capture->pdu[capture->count], pdu, pdu_len);
        capture->pdu_len[capture->count] = pdu_len;
    }
    if (capture != NULL) {
        capture->count++;
    }

    return 0;
}

static int memory_open_read(void *user, const char *path, void **handle,
                            uint32_t *size)
{
    struct memory_filestore *store = user;

    zassert_not_null(store);
    zassert_equal(strcmp(path, "src.bin"), 0);

    *handle = store;
    *size = store->size;
    return 0;
}

static int memory_read(void *user, void *handle, uint32_t offset, uint8_t *buf,
                       size_t len, size_t *nread)
{
    struct memory_filestore *store = user;
    size_t remaining;

    zassert_equal(handle, store);
    zassert_true(offset < store->size);
    zassert_not_null(buf);
    zassert_not_null(nread);

    remaining = store->size - offset;
    *nread = remaining < len ? remaining : len;
    memcpy(buf, &store->data[offset], *nread);
    store->read_count++;

    return 0;
}

static int memory_close(void *user, void *handle)
{
    struct memory_filestore *store = user;

    zassert_equal(handle, store);
    store->close_count++;
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

static ccsds_cfdp_ut_ops_t capture_ut(struct send_capture *capture)
{
    return (ccsds_cfdp_ut_ops_t){
        .user = capture,
        .send_pdu = test_send_pdu,
        .now_ms = NULL,
    };
}

static ccsds_cfdp_filestore_ops_t memory_filestore_ops(
    struct memory_filestore *store)
{
    return (ccsds_cfdp_filestore_ops_t){
        .user = store,
        .open_read = memory_open_read,
        .open_write_tmp = NULL,
        .read = memory_read,
        .write = NULL,
        .close = memory_close,
        .commit_tmp = NULL,
        .discard_tmp = NULL,
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

static void init_entity_with_capture(ccsds_cfdp_entity_t *entity,
                                     struct send_capture *capture)
{
    const ccsds_cfdp_entity_config_t config = base_config();
    const ccsds_cfdp_ut_ops_t ut = capture_ut(capture);

    memset(entity, 0xa5, sizeof(*entity));
    memset(capture, 0, sizeof(*capture));
    zassert_equal(ccsds_cfdp_entity_init(entity, &config, &ut),
                  CCSDS_CFDP_STATUS_OK);
}

static ccsds_cfdp_put_request_t base_put_request(void)
{
    return (ccsds_cfdp_put_request_t){
        .source_path = "src.bin",
        .destination_path = "dst.bin",
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        .closure_requested = true,
    };
}

static uint32_t modular_checksum(const uint8_t *data, size_t len)
{
    ccsds_cfdp_checksum_state_t state;
    uint32_t checksum;

    zassert_equal(ccsds_cfdp_checksum_init(
                      &state, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_update(&state, 0u, data, len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_checksum_finish(&state, &checksum),
                  CCSDS_CFDP_STATUS_OK);
    return checksum;
}

static void assert_sender_header(const ccsds_cfdp_pdu_header_t *header,
                                 enum ccsds_cfdp_pdu_type pdu_type,
                                 uint64_t sequence)
{
    zassert_equal(header->pdu_type, pdu_type);
    zassert_equal(header->direction, CCSDS_CFDP_DIRECTION_TOWARD_RECEIVER);
    zassert_equal(header->transmission_mode,
                  CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED);
    zassert_equal(header->source_entity_id, 0x12u);
    zassert_equal(header->destination_entity_id, 0x34u);
    zassert_equal(header->transaction_sequence_number, sequence);
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

ZTEST(ccsds_cfdp_entity, test_send_file_emits_metadata_filedata_and_eof)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    const uint8_t file[] = { 0x11u, 0x22u, 0x33u, 0x44u, 0x55u };
    struct memory_filestore store = {
        .data = file,
        .size = sizeof(file),
    };
    ccsds_cfdp_filestore_ops_t filestore = memory_filestore_ops(&store);
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;
    ccsds_cfdp_metadata_pdu_t metadata;
    ccsds_cfdp_filedata_pdu_t filedata;
    ccsds_cfdp_eof_pdu_t eof;
    size_t consumed;

    init_entity_with_capture(&entity, &capture);

    zassert_equal(ccsds_cfdp_entity_send_file(&entity, &filestore, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(id.source_entity_id, 0x12u);
    zassert_equal(id.transaction_sequence_number, 7u);
    zassert_false(entity.sender.active);
    zassert_equal(capture.count, 3u);
    zassert_equal(store.read_count, 1u);
    zassert_equal(store.close_count, 1u);

    zassert_equal(ccsds_cfdp_decode_metadata(capture.pdu[0],
                                             capture.pdu_len[0], &metadata,
                                             &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, capture.pdu_len[0]);
    assert_sender_header(&metadata.header,
                         CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE, 7u);
    zassert_true(metadata.closure_requested);
    zassert_equal(metadata.checksum_type, CCSDS_CFDP_CHECKSUM_TYPE_MODULAR);
    zassert_equal(metadata.file_size, sizeof(file));
    zassert_equal(metadata.source_filename.len, strlen("src.bin"));
    zassert_mem_equal(metadata.source_filename.value, "src.bin",
                      strlen("src.bin"));
    zassert_equal(metadata.destination_filename.len, strlen("dst.bin"));
    zassert_mem_equal(metadata.destination_filename.value, "dst.bin",
                      strlen("dst.bin"));

    zassert_equal(ccsds_cfdp_decode_filedata(capture.pdu[1],
                                             capture.pdu_len[1], &filedata,
                                             &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, capture.pdu_len[1]);
    assert_sender_header(&filedata.header, CCSDS_CFDP_PDU_TYPE_FILE_DATA, 7u);
    zassert_equal(filedata.offset, 0u);
    zassert_equal(filedata.data_len, sizeof(file));
    zassert_mem_equal(filedata.data, file, sizeof(file));

    zassert_equal(ccsds_cfdp_decode_eof(capture.pdu[2], capture.pdu_len[2],
                                        &eof, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, capture.pdu_len[2]);
    assert_sender_header(&eof.header, CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE, 7u);
    zassert_equal(eof.condition_code, CCSDS_CFDP_CONDITION_NO_ERROR);
    zassert_equal(eof.file_size, sizeof(file));
    zassert_equal(eof.file_checksum, modular_checksum(file, sizeof(file)));
}

ZTEST(ccsds_cfdp_entity, test_send_file_segments_over_multiple_filedata_pdus)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    uint8_t file[(2u * CCSDS_CFDP_MAX_SEGMENT_SIZE) + 5u];
    struct memory_filestore store = {
        .data = file,
        .size = sizeof(file),
    };
    ccsds_cfdp_filestore_ops_t filestore = memory_filestore_ops(&store);
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;
    ccsds_cfdp_filedata_pdu_t first;
    ccsds_cfdp_filedata_pdu_t second;
    ccsds_cfdp_filedata_pdu_t third;
    ccsds_cfdp_eof_pdu_t eof;
    size_t consumed;

    for (size_t i = 0u; i < sizeof(file); i++) {
        file[i] = (uint8_t)(i & 0xffu);
    }

    init_entity_with_capture(&entity, &capture);

    zassert_equal(ccsds_cfdp_entity_send_file(&entity, &filestore, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(capture.count, 5u);
    zassert_equal(store.read_count, 3u);

    zassert_equal(ccsds_cfdp_decode_filedata(capture.pdu[1],
                                             capture.pdu_len[1], &first,
                                             &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_decode_filedata(capture.pdu[2],
                                             capture.pdu_len[2], &second,
                                             &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_decode_filedata(capture.pdu[3],
                                             capture.pdu_len[3], &third,
                                             &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(first.offset, 0u);
    zassert_equal(first.data_len, CCSDS_CFDP_MAX_SEGMENT_SIZE);
    zassert_mem_equal(first.data, &file[0], CCSDS_CFDP_MAX_SEGMENT_SIZE);
    zassert_equal(second.offset, CCSDS_CFDP_MAX_SEGMENT_SIZE);
    zassert_equal(second.data_len, CCSDS_CFDP_MAX_SEGMENT_SIZE);
    zassert_mem_equal(second.data, &file[CCSDS_CFDP_MAX_SEGMENT_SIZE],
                      CCSDS_CFDP_MAX_SEGMENT_SIZE);
    zassert_equal(third.offset, 2u * CCSDS_CFDP_MAX_SEGMENT_SIZE);
    zassert_equal(third.data_len, 5u);
    zassert_mem_equal(third.data, &file[2u * CCSDS_CFDP_MAX_SEGMENT_SIZE],
                      5u);

    zassert_equal(ccsds_cfdp_decode_eof(capture.pdu[4], capture.pdu_len[4],
                                        &eof, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(eof.file_size, sizeof(file));
    zassert_equal(eof.file_checksum, modular_checksum(file, sizeof(file)));
}

ZTEST(ccsds_cfdp_entity, test_send_file_accumulates_checksum_while_sending)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    uint8_t file[CCSDS_CFDP_MAX_SEGMENT_SIZE + 3u];
    struct memory_filestore store = {
        .data = file,
        .size = sizeof(file),
    };
    ccsds_cfdp_filestore_ops_t filestore = memory_filestore_ops(&store);
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;
    ccsds_cfdp_eof_pdu_t eof;
    size_t consumed;

    for (size_t i = 0u; i < sizeof(file); i++) {
        file[i] = (uint8_t)(0xa0u + (i & 0x0fu));
    }

    init_entity_with_capture(&entity, &capture);

    zassert_equal(ccsds_cfdp_entity_send_file(&entity, &filestore, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(store.read_count, 2u);
    zassert_equal(capture.count, 4u);
    zassert_equal(ccsds_cfdp_decode_eof(capture.pdu[3], capture.pdu_len[3],
                                        &eof, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(eof.file_checksum, modular_checksum(file, sizeof(file)));
}

ZTEST(ccsds_cfdp_entity, test_send_file_rejects_second_simultaneous_sender)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    const uint8_t file[] = { 0x01u };
    struct memory_filestore store = {
        .data = file,
        .size = sizeof(file),
    };
    ccsds_cfdp_filestore_ops_t filestore = memory_filestore_ops(&store);
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;

    init_entity_with_capture(&entity, &capture);

    zassert_equal(ccsds_cfdp_entity_create_sender_transaction(&entity, &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_send_file(&entity, &filestore, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_TRANSACTION_BUSY);
    zassert_true(entity.sender.active);
    zassert_equal(capture.count, 0u);
    zassert_equal(store.read_count, 0u);
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
