#include <zephyr/ztest.h>

#include <stdbool.h>
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

struct receive_file {
    bool exists;
    bool open;
    char path[CCSDS_CFDP_MAX_FILENAME_LEN + 1u];
    uint8_t data[(4u * CCSDS_CFDP_MAX_SEGMENT_SIZE) + 16u];
    uint32_t size;
};

struct receive_filestore {
    struct receive_file tmp;
    struct receive_file dst;
    uint32_t write_count;
    uint32_t read_count;
    uint32_t close_count;
    uint32_t commit_count;
    uint32_t discard_count;
};

struct closure_loopback_endpoint;

struct closure_loopback {
    ccsds_cfdp_entity_t *sender;
    ccsds_cfdp_entity_t *receiver;
    ccsds_cfdp_filestore_ops_t *source_ops;
    ccsds_cfdp_filestore_ops_t *dest_ops;
    struct closure_loopback_endpoint *sender_endpoint;
    struct closure_loopback_endpoint *receiver_endpoint;
    bool drop_filedata_enabled;
    uint32_t drop_filedata_offset;
    uint32_t drop_filedata_offsets[CCSDS_CFDP_MAX_NAK_RANGES];
    uint32_t drop_filedata_offset_count;
    uint32_t drop_filedata_drop_counts[CCSDS_CFDP_MAX_NAK_RANGES];
    bool drop_filedata_once;
    uint32_t sender_to_receiver_count;
    uint32_t receiver_to_sender_count;
    uint32_t dropped_count;
    enum ccsds_cfdp_status last_receiver_status;
    enum ccsds_cfdp_status last_sender_status;
};

struct closure_loopback_endpoint {
    struct closure_loopback *loopback;
    uint64_t local_entity_id;
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

static uint64_t test_now_ms(void *user)
{
    ARG_UNUSED(user);

    return 1000u;
}

static int closure_loopback_send_pdu(void *user, uint64_t dest_entity_id,
                                     const uint8_t *pdu, size_t pdu_len)
{
    struct closure_loopback_endpoint *endpoint = user;
    struct closure_loopback *loopback;
    ccsds_cfdp_pdu_header_t header;
    size_t consumed;

    zassert_not_null(endpoint);
    zassert_not_null(endpoint->loopback);
    zassert_not_null(pdu);

    loopback = endpoint->loopback;
    zassert_equal(ccsds_cfdp_decode_header(pdu, pdu_len, &header, &consumed),
                  CCSDS_CFDP_STATUS_OK);

    if (dest_entity_id == loopback->receiver_endpoint->local_entity_id) {
        loopback->sender_to_receiver_count++;
        if (loopback->drop_filedata_enabled &&
            header.pdu_type == CCSDS_CFDP_PDU_TYPE_FILE_DATA) {
            ccsds_cfdp_filedata_pdu_t filedata;
            bool drop = false;

            zassert_equal(ccsds_cfdp_decode_filedata(pdu, pdu_len, &filedata,
                                                     &consumed),
                          CCSDS_CFDP_STATUS_OK);
            if (loopback->drop_filedata_offset_count == 0u) {
                drop = filedata.offset == loopback->drop_filedata_offset;
                if (loopback->drop_filedata_once &&
                    loopback->dropped_count > 0u) {
                    drop = false;
                }
            }
            for (uint32_t i = 0u;
                 i < loopback->drop_filedata_offset_count; i++) {
                if (filedata.offset == loopback->drop_filedata_offsets[i]) {
                    if (!loopback->drop_filedata_once ||
                        loopback->drop_filedata_drop_counts[i] == 0u) {
                        drop = true;
                        loopback->drop_filedata_drop_counts[i]++;
                    }
                    break;
                }
            }
            if (drop) {
                loopback->dropped_count++;
                return 0;
            }
        }

        loopback->last_receiver_status = ccsds_cfdp_entity_receive_pdu(
            loopback->receiver, loopback->dest_ops, pdu, pdu_len);
        return 0;
    }

    if (dest_entity_id == loopback->sender_endpoint->local_entity_id) {
        loopback->receiver_to_sender_count++;
        loopback->last_sender_status =
            ccsds_cfdp_entity_receive_pdu(loopback->sender,
                                          loopback->source_ops, pdu, pdu_len);
        return 0;
    }

    return -1;
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

static int receive_open_write_tmp(void *user, const char *dst_path,
                                  void **handle)
{
    struct receive_filestore *store = user;
    size_t path_len;

    zassert_not_null(store);
    zassert_not_null(dst_path);
    zassert_not_null(handle);

    path_len = strlen(dst_path);
    zassert_true(path_len > 0u);
    zassert_true(path_len <= CCSDS_CFDP_MAX_FILENAME_LEN);

    memset(&store->tmp, 0, sizeof(store->tmp));
    store->tmp.exists = true;
    store->tmp.open = true;
    memcpy(store->tmp.path, dst_path, path_len + 1u);
    *handle = &store->tmp;
    return 0;
}

static int receive_read(void *user, void *handle, uint32_t offset,
                        uint8_t *buf, size_t len, size_t *nread)
{
    struct receive_filestore *store = user;
    struct receive_file *file = handle;
    uint32_t available;

    zassert_not_null(store);
    zassert_not_null(file);
    zassert_not_null(buf);
    zassert_not_null(nread);
    zassert_true(file->exists);

    if (offset >= file->size) {
        *nread = 0u;
        return 0;
    }

    available = file->size - offset;
    if (len > available) {
        len = available;
    }

    memcpy(buf, &file->data[offset], len);
    *nread = len;
    store->read_count++;
    return 0;
}

static int receive_write(void *user, void *handle, uint32_t offset,
                         const uint8_t *buf, size_t len)
{
    struct receive_filestore *store = user;
    struct receive_file *file = handle;
    size_t end;

    zassert_not_null(store);
    zassert_not_null(file);
    zassert_not_null(buf);
    zassert_true(file->exists);
    zassert_true(file->open);

    end = (size_t)offset + len;
    zassert_true(end <= sizeof(file->data));

    memcpy(&file->data[offset], buf, len);
    if (end > file->size) {
        file->size = end;
    }
    store->write_count++;
    return 0;
}

static int receive_close(void *user, void *handle)
{
    struct receive_filestore *store = user;
    struct receive_file *file = handle;

    zassert_not_null(store);
    zassert_not_null(file);
    zassert_true(file->exists);
    zassert_true(file->open);

    file->open = false;
    store->close_count++;
    return 0;
}

static int receive_commit_tmp(void *user, const char *dst_path)
{
    struct receive_filestore *store = user;

    zassert_not_null(store);
    zassert_not_null(dst_path);
    zassert_true(store->tmp.exists);
    zassert_false(store->tmp.open);
    zassert_equal(strcmp(store->tmp.path, dst_path), 0);

    memset(&store->dst, 0, sizeof(store->dst));
    store->dst.exists = true;
    memcpy(store->dst.path, store->tmp.path, strlen(store->tmp.path) + 1u);
    memcpy(store->dst.data, store->tmp.data, store->tmp.size);
    store->dst.size = store->tmp.size;
    memset(&store->tmp, 0, sizeof(store->tmp));
    store->commit_count++;
    return 0;
}

static int receive_discard_tmp(void *user, const char *dst_path)
{
    struct receive_filestore *store = user;

    zassert_not_null(store);
    zassert_not_null(dst_path);
    zassert_equal(strcmp(store->tmp.path, dst_path), 0);

    memset(&store->tmp, 0, sizeof(store->tmp));
    store->discard_count++;
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

static ccsds_cfdp_ut_ops_t capture_ut_with_clock(struct send_capture *capture)
{
    return (ccsds_cfdp_ut_ops_t){
        .user = capture,
        .send_pdu = test_send_pdu,
        .now_ms = test_now_ms,
    };
}

static ccsds_cfdp_ut_ops_t closure_ut(struct closure_loopback_endpoint *endpoint)
{
    return (ccsds_cfdp_ut_ops_t){
        .user = endpoint,
        .send_pdu = closure_loopback_send_pdu,
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

static ccsds_cfdp_filestore_ops_t receive_filestore_ops(
    struct receive_filestore *store)
{
    return (ccsds_cfdp_filestore_ops_t){
        .user = store,
        .open_read = NULL,
        .open_write_tmp = receive_open_write_tmp,
        .read = receive_read,
        .write = receive_write,
        .close = receive_close,
        .commit_tmp = receive_commit_tmp,
        .discard_tmp = receive_discard_tmp,
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

static void init_entity_with_capture_and_clock(ccsds_cfdp_entity_t *entity,
                                               struct send_capture *capture)
{
    const ccsds_cfdp_entity_config_t config = base_config();
    const ccsds_cfdp_ut_ops_t ut = capture_ut_with_clock(capture);

    memset(entity, 0xa5, sizeof(*entity));
    memset(capture, 0, sizeof(*capture));
    zassert_equal(ccsds_cfdp_entity_init(entity, &config, &ut),
                  CCSDS_CFDP_STATUS_OK);
}

static void init_entity_with_config(ccsds_cfdp_entity_t *entity,
                                    uint64_t local_entity_id,
                                    uint64_t remote_entity_id)
{
    ccsds_cfdp_entity_config_t config = base_config();
    const ccsds_cfdp_ut_ops_t ut = base_ut();

    config.local_entity_id = local_entity_id;
    config.remote_entity_id = remote_entity_id;

    memset(entity, 0xa5, sizeof(*entity));
    zassert_equal(ccsds_cfdp_entity_init(entity, &config, &ut),
                  CCSDS_CFDP_STATUS_OK);
}

static void init_entity_with_custom_ut(ccsds_cfdp_entity_t *entity,
                                       uint64_t local_entity_id,
                                       uint64_t remote_entity_id,
                                       const ccsds_cfdp_ut_ops_t *ut)
{
    ccsds_cfdp_entity_config_t config = base_config();

    config.local_entity_id = local_entity_id;
    config.remote_entity_id = remote_entity_id;

    memset(entity, 0xa5, sizeof(*entity));
    zassert_equal(ccsds_cfdp_entity_init(entity, &config, ut),
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

static ccsds_cfdp_put_request_t acknowledged_put_request(void)
{
    ccsds_cfdp_put_request_t request = base_put_request();

    request.acknowledged_mode = true;
    return request;
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

static ccsds_cfdp_pdu_header_t incoming_header(
    enum ccsds_cfdp_pdu_type pdu_type, uint64_t sequence)
{
    return (ccsds_cfdp_pdu_header_t){
        .version = CCSDS_CFDP_VERSION_1,
        .pdu_type = pdu_type,
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
        .source_entity_id = 0x34u,
        .transaction_sequence_number = sequence,
        .destination_entity_id = 0x12u,
    };
}

static ccsds_cfdp_pdu_header_t incoming_ack_header(
    enum ccsds_cfdp_pdu_type pdu_type, uint64_t sequence)
{
    ccsds_cfdp_pdu_header_t header = incoming_header(pdu_type, sequence);

    header.transmission_mode = CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED;
    return header;
}

static void encode_incoming_metadata(uint64_t sequence, uint32_t file_size,
                                     uint8_t *buf, size_t cap, size_t *len)
{
    const char src[] = "src.bin";
    const char dst[] = "dst.bin";
    const ccsds_cfdp_metadata_pdu_t metadata = {
        .header = incoming_header(CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
                                  sequence),
        .closure_requested = true,
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        .file_size = file_size,
        .source_filename = {
            .value = (const uint8_t *)src,
            .len = (uint8_t)strlen(src),
        },
        .destination_filename = {
            .value = (const uint8_t *)dst,
            .len = (uint8_t)strlen(dst),
        },
    };

    zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
}

static void encode_incoming_ack_metadata(uint64_t sequence, uint32_t file_size,
                                         uint8_t *buf, size_t cap,
                                         size_t *len)
{
    const char src[] = "src.bin";
    const char dst[] = "dst.bin";
    const ccsds_cfdp_metadata_pdu_t metadata = {
        .header = incoming_ack_header(CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
                                      sequence),
        .closure_requested = false,
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        .file_size = file_size,
        .source_filename = {
            .value = (const uint8_t *)src,
            .len = (uint8_t)strlen(src),
        },
        .destination_filename = {
            .value = (const uint8_t *)dst,
            .len = (uint8_t)strlen(dst),
        },
    };

    zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
}

static void encode_incoming_filedata(uint64_t sequence, uint32_t offset,
                                     const uint8_t *data, size_t data_len,
                                     uint8_t *buf, size_t cap, size_t *len)
{
    const ccsds_cfdp_filedata_pdu_t filedata = {
        .header = incoming_header(CCSDS_CFDP_PDU_TYPE_FILE_DATA, sequence),
        .offset = offset,
        .data = data,
        .data_len = data_len,
    };

    zassert_equal(ccsds_cfdp_encode_filedata(&filedata, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
}

static void encode_incoming_ack_filedata(uint64_t sequence, uint32_t offset,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *buf, size_t cap,
                                         size_t *len)
{
    const ccsds_cfdp_filedata_pdu_t filedata = {
        .header = incoming_ack_header(CCSDS_CFDP_PDU_TYPE_FILE_DATA, sequence),
        .offset = offset,
        .data = data,
        .data_len = data_len,
    };

    zassert_equal(ccsds_cfdp_encode_filedata(&filedata, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
}

static void encode_incoming_eof(uint64_t sequence, uint32_t checksum,
                                uint32_t file_size, uint8_t *buf, size_t cap,
                                size_t *len)
{
    const ccsds_cfdp_eof_pdu_t eof = {
        .header = incoming_header(CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
                                  sequence),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .file_checksum = checksum,
        .file_size = file_size,
    };

    zassert_equal(ccsds_cfdp_encode_eof(&eof, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
}

static void encode_incoming_ack_eof(uint64_t sequence, uint32_t checksum,
                                    uint32_t file_size, uint8_t *buf,
                                    size_t cap, size_t *len)
{
    const ccsds_cfdp_eof_pdu_t eof = {
        .header = incoming_ack_header(CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
                                      sequence),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .file_checksum = checksum,
        .file_size = file_size,
    };

    zassert_equal(ccsds_cfdp_encode_eof(&eof, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
}

static void encode_sender_nak(uint64_t sequence, uint32_t scope_start,
                              uint32_t scope_end,
                              const ccsds_cfdp_nak_range_t *ranges,
                              size_t range_count, uint8_t *buf, size_t cap,
                              size_t *len)
{
    ccsds_cfdp_nak_pdu_t nak = {
        .header = {
            .version = CCSDS_CFDP_VERSION_1,
            .pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
            .direction = CCSDS_CFDP_DIRECTION_TOWARD_SENDER,
            .transmission_mode =
                CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED,
            .crc_flag = CCSDS_CFDP_CRC_NOT_PRESENT,
            .file_size_mode = CCSDS_CFDP_FILE_SIZE_SMALL,
            .pdu_data_field_len = 0u,
            .segmentation_control =
                CCSDS_CFDP_SEGMENTATION_RECORD_BOUNDARIES_NOT_PRESERVED,
            .segment_metadata_present = false,
            .entity_id_len = 1u,
            .transaction_sequence_number_len = 1u,
            .source_entity_id = 0x12u,
            .transaction_sequence_number = sequence,
            .destination_entity_id = 0x34u,
        },
        .scope_start = scope_start,
        .scope_end = scope_end,
        .range_count = range_count,
    };

    for (size_t i = 0u; i < range_count; i++) {
        nak.ranges[i] = ranges[i];
    }

    zassert_equal(ccsds_cfdp_encode_nak(&nak, buf, cap, len),
                  CCSDS_CFDP_STATUS_OK);
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

ZTEST(ccsds_cfdp_entity, test_send_file_reports_timeout_without_finished)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    const uint8_t file[] = { 0x42u };
    struct memory_filestore store = {
        .data = file,
        .size = sizeof(file),
    };
    ccsds_cfdp_filestore_ops_t filestore = memory_filestore_ops(&store);
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;

    init_entity_with_capture_and_clock(&entity, &capture);

    zassert_equal(ccsds_cfdp_entity_send_file(&entity, &filestore, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_INACTIVITY_DETECTED);

    zassert_false(entity.sender.active);
    zassert_equal(capture.count, 3u);
    zassert_equal(store.close_count, 1u);
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

ZTEST(ccsds_cfdp_entity, test_receive_loopback_commits_destination_file)
{
    ccsds_cfdp_entity_t sender;
    ccsds_cfdp_entity_t receiver;
    struct send_capture capture;
    const uint8_t file[] = { 'A', 'k', 'i', 'r', 'a' };
    struct memory_filestore source_store = {
        .data = file,
        .size = sizeof(file),
    };
    struct receive_filestore dest_store;
    ccsds_cfdp_filestore_ops_t source_ops =
        memory_filestore_ops(&source_store);
    ccsds_cfdp_filestore_ops_t dest_ops = receive_filestore_ops(&dest_store);
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;

    memset(&dest_store, 0, sizeof(dest_store));
    init_entity_with_capture(&sender, &capture);
    init_entity_with_config(&receiver, 0x34u, 0x12u);

    zassert_equal(ccsds_cfdp_entity_send_file(&sender, &source_ops, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(capture.count, 3u);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&receiver, &dest_ops,
                                                capture.pdu[0],
                                                capture.pdu_len[0]),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&receiver, &dest_ops,
                                                capture.pdu[1],
                                                capture.pdu_len[1]),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&receiver, &dest_ops,
                                                capture.pdu[2],
                                                capture.pdu_len[2]),
                  CCSDS_CFDP_STATUS_OK);

    zassert_false(receiver.receiver.active);
    zassert_true(dest_store.dst.exists);
    zassert_equal(strcmp(dest_store.dst.path, "dst.bin"), 0);
    zassert_equal(dest_store.dst.size, sizeof(file));
    zassert_mem_equal(dest_store.dst.data, file, sizeof(file));
    zassert_equal(dest_store.commit_count, 1u);
    zassert_equal(dest_store.discard_count, 0u);
}

ZTEST(ccsds_cfdp_entity, test_class1_closure_loopback_reports_sender_success)
{
    ccsds_cfdp_entity_t sender;
    ccsds_cfdp_entity_t receiver;
    struct closure_loopback loopback;
    struct closure_loopback_endpoint sender_endpoint;
    struct closure_loopback_endpoint receiver_endpoint;
    const uint8_t file[] = { 'C', 'F', 'D', 'P' };
    struct memory_filestore source_store = {
        .data = file,
        .size = sizeof(file),
    };
    struct receive_filestore dest_store;
    ccsds_cfdp_filestore_ops_t source_ops =
        memory_filestore_ops(&source_store);
    ccsds_cfdp_filestore_ops_t dest_ops = receive_filestore_ops(&dest_store);
    ccsds_cfdp_ut_ops_t sender_ut;
    ccsds_cfdp_ut_ops_t receiver_ut;
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;

    memset(&loopback, 0, sizeof(loopback));
    memset(&sender_endpoint, 0, sizeof(sender_endpoint));
    memset(&receiver_endpoint, 0, sizeof(receiver_endpoint));
    memset(&dest_store, 0, sizeof(dest_store));

    loopback.sender = &sender;
    loopback.receiver = &receiver;
    loopback.source_ops = &source_ops;
    loopback.dest_ops = &dest_ops;
    loopback.sender_endpoint = &sender_endpoint;
    loopback.receiver_endpoint = &receiver_endpoint;
    sender_endpoint.loopback = &loopback;
    sender_endpoint.local_entity_id = 0x12u;
    receiver_endpoint.loopback = &loopback;
    receiver_endpoint.local_entity_id = 0x34u;
    sender_ut = closure_ut(&sender_endpoint);
    receiver_ut = closure_ut(&receiver_endpoint);

    init_entity_with_custom_ut(&sender, 0x12u, 0x34u, &sender_ut);
    init_entity_with_custom_ut(&receiver, 0x34u, 0x12u, &receiver_ut);

    zassert_equal(ccsds_cfdp_entity_send_file(&sender, &source_ops, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);

    zassert_false(sender.sender.active);
    zassert_false(receiver.receiver.active);
    zassert_true(dest_store.dst.exists);
    zassert_equal(dest_store.dst.size, sizeof(file));
    zassert_mem_equal(dest_store.dst.data, file, sizeof(file));
    zassert_equal(loopback.sender_to_receiver_count, 3u);
    zassert_equal(loopback.receiver_to_sender_count, 1u);
    zassert_equal(loopback.last_receiver_status, CCSDS_CFDP_STATUS_OK);
    zassert_equal(loopback.last_sender_status, CCSDS_CFDP_STATUS_OK);
}

ZTEST(ccsds_cfdp_entity, test_class1_closure_loopback_reports_sender_failure)
{
    ccsds_cfdp_entity_t sender;
    ccsds_cfdp_entity_t receiver;
    struct closure_loopback loopback;
    struct closure_loopback_endpoint sender_endpoint;
    struct closure_loopback_endpoint receiver_endpoint;
    const uint8_t file[] = { 'l', 'o', 's', 's' };
    struct memory_filestore source_store = {
        .data = file,
        .size = sizeof(file),
    };
    struct receive_filestore dest_store;
    ccsds_cfdp_filestore_ops_t source_ops =
        memory_filestore_ops(&source_store);
    ccsds_cfdp_filestore_ops_t dest_ops = receive_filestore_ops(&dest_store);
    ccsds_cfdp_ut_ops_t sender_ut;
    ccsds_cfdp_ut_ops_t receiver_ut;
    const ccsds_cfdp_put_request_t request = base_put_request();
    ccsds_cfdp_transaction_id_t id;

    memset(&loopback, 0, sizeof(loopback));
    memset(&sender_endpoint, 0, sizeof(sender_endpoint));
    memset(&receiver_endpoint, 0, sizeof(receiver_endpoint));
    memset(&dest_store, 0, sizeof(dest_store));

    loopback.sender = &sender;
    loopback.receiver = &receiver;
    loopback.source_ops = &source_ops;
    loopback.dest_ops = &dest_ops;
    loopback.sender_endpoint = &sender_endpoint;
    loopback.receiver_endpoint = &receiver_endpoint;
    loopback.drop_filedata_enabled = true;
    loopback.drop_filedata_offset = 0u;
    sender_endpoint.loopback = &loopback;
    sender_endpoint.local_entity_id = 0x12u;
    receiver_endpoint.loopback = &loopback;
    receiver_endpoint.local_entity_id = 0x34u;
    sender_ut = closure_ut(&sender_endpoint);
    receiver_ut = closure_ut(&receiver_endpoint);

    init_entity_with_custom_ut(&sender, 0x12u, 0x34u, &sender_ut);
    init_entity_with_custom_ut(&receiver, 0x34u, 0x12u, &receiver_ut);

    zassert_equal(ccsds_cfdp_entity_send_file(&sender, &source_ops, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);

    zassert_false(sender.sender.active);
    zassert_false(receiver.receiver.active);
    zassert_false(dest_store.dst.exists);
    zassert_equal(dest_store.discard_count, 1u);
    zassert_equal(loopback.dropped_count, 1u);
    zassert_equal(loopback.receiver_to_sender_count, 1u);
    zassert_equal(loopback.last_receiver_status,
                  CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
    zassert_equal(loopback.last_sender_status,
                  CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
}

ZTEST(ccsds_cfdp_entity, test_receive_out_of_order_filedata_commits_file)
{
    ccsds_cfdp_entity_t entity;
    struct receive_filestore store;
    ccsds_cfdp_filestore_ops_t ops = receive_filestore_ops(&store);
    const uint8_t file[] = { 'A', 'B', 'C', 'D', 'E', 'F' };
    uint8_t metadata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t tail[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t head[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t eof[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t metadata_len;
    size_t tail_len;
    size_t head_len;
    size_t eof_len;

    memset(&store, 0, sizeof(store));
    init_entity(&entity);
    encode_incoming_metadata(0x44u, sizeof(file), metadata, sizeof(metadata),
                             &metadata_len);
    encode_incoming_filedata(0x44u, 3u, &file[3], 3u, tail, sizeof(tail),
                             &tail_len);
    encode_incoming_filedata(0x44u, 0u, file, 3u, head, sizeof(head),
                             &head_len);
    encode_incoming_eof(0x44u, modular_checksum(file, sizeof(file)),
                        sizeof(file), eof, sizeof(eof), &eof_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, metadata,
                                                metadata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, tail,
                                                tail_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, head,
                                                head_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, eof, eof_len),
                  CCSDS_CFDP_STATUS_OK);

    zassert_true(store.dst.exists);
    zassert_equal(store.dst.size, sizeof(file));
    zassert_mem_equal(store.dst.data, file, sizeof(file));
    zassert_equal(store.write_count, 2u);
}

ZTEST(ccsds_cfdp_entity, test_receive_rejects_filedata_before_metadata)
{
    ccsds_cfdp_entity_t entity;
    struct receive_filestore store;
    ccsds_cfdp_filestore_ops_t ops = receive_filestore_ops(&store);
    const uint8_t file[] = { 1u, 2u };
    uint8_t pdu[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t pdu_len;

    memset(&store, 0, sizeof(store));
    init_entity(&entity);
    encode_incoming_filedata(0x45u, 0u, file, sizeof(file), pdu, sizeof(pdu),
                             &pdu_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, pdu, pdu_len),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_false(entity.receiver.active);
    zassert_false(store.tmp.exists);
    zassert_false(store.dst.exists);
}

ZTEST(ccsds_cfdp_entity, test_receive_eof_with_missing_data_reports_incomplete)
{
    ccsds_cfdp_entity_t entity;
    struct receive_filestore store;
    ccsds_cfdp_filestore_ops_t ops = receive_filestore_ops(&store);
    const uint8_t file[] = { 1u, 2u, 3u, 4u };
    uint8_t metadata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t filedata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t eof[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t metadata_len;
    size_t filedata_len;
    size_t eof_len;

    memset(&store, 0, sizeof(store));
    init_entity(&entity);
    encode_incoming_metadata(0x46u, sizeof(file), metadata, sizeof(metadata),
                             &metadata_len);
    encode_incoming_filedata(0x46u, 0u, file, 2u, filedata, sizeof(filedata),
                             &filedata_len);
    encode_incoming_eof(0x46u, modular_checksum(file, sizeof(file)),
                        sizeof(file), eof, sizeof(eof), &eof_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, metadata,
                                                metadata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, filedata,
                                                filedata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, eof, eof_len),
                  CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);

    zassert_false(entity.receiver.active);
    zassert_false(store.dst.exists);
    zassert_equal(store.discard_count, 1u);
}

ZTEST(ccsds_cfdp_entity, test_receive_eof_with_bad_checksum_reports_failure)
{
    ccsds_cfdp_entity_t entity;
    struct receive_filestore store;
    ccsds_cfdp_filestore_ops_t ops = receive_filestore_ops(&store);
    const uint8_t file[] = { 9u, 8u, 7u, 6u };
    uint8_t metadata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t filedata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t eof[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t metadata_len;
    size_t filedata_len;
    size_t eof_len;

    memset(&store, 0, sizeof(store));
    init_entity(&entity);
    encode_incoming_metadata(0x47u, sizeof(file), metadata, sizeof(metadata),
                             &metadata_len);
    encode_incoming_filedata(0x47u, 0u, file, sizeof(file), filedata,
                             sizeof(filedata), &filedata_len);
    encode_incoming_eof(0x47u, modular_checksum(file, sizeof(file)) + 1u,
                        sizeof(file), eof, sizeof(eof), &eof_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, metadata,
                                                metadata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, filedata,
                                                filedata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, eof, eof_len),
                  CCSDS_CFDP_STATUS_CHECKSUM_FAILURE);

    zassert_false(entity.receiver.active);
    zassert_false(store.dst.exists);
    zassert_equal(store.discard_count, 1u);
}

ZTEST(ccsds_cfdp_entity, test_acknowledged_receiver_sends_eof_ack_and_nak)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    struct receive_filestore store;
    ccsds_cfdp_filestore_ops_t ops = receive_filestore_ops(&store);
    const uint8_t file[] = { 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u };
    uint8_t metadata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t filedata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t eof[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t metadata_len;
    size_t filedata_len;
    size_t eof_len;
    ccsds_cfdp_ack_pdu_t ack;
    ccsds_cfdp_nak_pdu_t nak;
    size_t consumed;

    memset(&store, 0, sizeof(store));
    init_entity_with_capture(&entity, &capture);
    encode_incoming_ack_metadata(0x50u, sizeof(file), metadata,
                                 sizeof(metadata), &metadata_len);
    encode_incoming_ack_filedata(0x50u, 0u, file, 4u, filedata,
                                 sizeof(filedata), &filedata_len);
    encode_incoming_ack_eof(0x50u, modular_checksum(file, sizeof(file)),
                            sizeof(file), eof, sizeof(eof), &eof_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, metadata,
                                                metadata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, filedata,
                                                filedata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, eof, eof_len),
                  CCSDS_CFDP_STATUS_OK);

    zassert_true(entity.receiver.active);
    zassert_true(store.tmp.exists);
    zassert_true(store.tmp.open);
    zassert_false(store.dst.exists);
    zassert_equal(store.discard_count, 0u);
    zassert_equal(capture.count, 2u);
    zassert_equal(capture.dest_entity_id[0], 0x34u);
    zassert_equal(capture.dest_entity_id[1], 0x34u);

    zassert_equal(ccsds_cfdp_decode_ack(capture.pdu[0], capture.pdu_len[0],
                                        &ack, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, capture.pdu_len[0]);
    zassert_equal(ack.header.direction, CCSDS_CFDP_DIRECTION_TOWARD_SENDER);
    zassert_equal(ack.header.transmission_mode,
                  CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED);
    zassert_equal(ack.header.source_entity_id, 0x34u);
    zassert_equal(ack.header.destination_entity_id, 0x12u);
    zassert_equal(ack.header.transaction_sequence_number, 0x50u);
    zassert_equal(ack.acknowledged_directive, CCSDS_CFDP_DIRECTIVE_EOF);
    zassert_equal(ack.transaction_status, CCSDS_CFDP_TRANSACTION_STATUS_ACTIVE);

    zassert_equal(ccsds_cfdp_decode_nak(capture.pdu[1], capture.pdu_len[1],
                                        &nak, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, capture.pdu_len[1]);
    zassert_equal(nak.scope_start, 0u);
    zassert_equal(nak.scope_end, sizeof(file));
    zassert_equal(nak.range_count, 1u);
    zassert_equal(nak.ranges[0].start, 4u);
    zassert_equal(nak.ranges[0].end, sizeof(file));
}

ZTEST(ccsds_cfdp_entity, test_acknowledged_receiver_nak_has_multiple_ranges)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    struct receive_filestore store;
    ccsds_cfdp_filestore_ops_t ops = receive_filestore_ops(&store);
    const uint8_t file[] = {
        0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u,
    };
    uint8_t metadata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t first[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t second[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t eof[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t metadata_len;
    size_t first_len;
    size_t second_len;
    size_t eof_len;
    ccsds_cfdp_nak_pdu_t nak;
    size_t consumed;

    memset(&store, 0, sizeof(store));
    init_entity_with_capture(&entity, &capture);
    encode_incoming_ack_metadata(0x51u, sizeof(file), metadata,
                                 sizeof(metadata), &metadata_len);
    encode_incoming_ack_filedata(0x51u, 0u, file, 2u, first, sizeof(first),
                                 &first_len);
    encode_incoming_ack_filedata(0x51u, 5u, &file[5], 2u, second,
                                 sizeof(second), &second_len);
    encode_incoming_ack_eof(0x51u, modular_checksum(file, sizeof(file)),
                            sizeof(file), eof, sizeof(eof), &eof_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, metadata,
                                                metadata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, first,
                                                first_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, second,
                                                second_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, eof, eof_len),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(capture.count, 2u);
    zassert_equal(ccsds_cfdp_decode_nak(capture.pdu[1], capture.pdu_len[1],
                                        &nak, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(nak.range_count, 2u);
    zassert_equal(nak.ranges[0].start, 2u);
    zassert_equal(nak.ranges[0].end, 5u);
    zassert_equal(nak.ranges[1].start, 7u);
    zassert_equal(nak.ranges[1].end, sizeof(file));
    zassert_true(entity.receiver.active);
    zassert_false(store.dst.exists);
}

ZTEST(ccsds_cfdp_entity, test_acknowledged_receiver_finishes_after_retransmit)
{
    ccsds_cfdp_entity_t entity;
    struct send_capture capture;
    struct receive_filestore store;
    ccsds_cfdp_filestore_ops_t ops = receive_filestore_ops(&store);
    const uint8_t file[] = { 'r', 'e', 'c', 'o', 'v', 'e', 'r' };
    uint8_t metadata[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t first[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t missing[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t eof[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t metadata_len;
    size_t first_len;
    size_t missing_len;
    size_t eof_len;
    ccsds_cfdp_finished_pdu_t finished;
    size_t consumed;

    memset(&store, 0, sizeof(store));
    init_entity_with_capture(&entity, &capture);
    encode_incoming_ack_metadata(0x52u, sizeof(file), metadata,
                                 sizeof(metadata), &metadata_len);
    encode_incoming_ack_filedata(0x52u, 0u, file, 3u, first, sizeof(first),
                                 &first_len);
    encode_incoming_ack_filedata(0x52u, 3u, &file[3], sizeof(file) - 3u,
                                 missing, sizeof(missing), &missing_len);
    encode_incoming_ack_eof(0x52u, modular_checksum(file, sizeof(file)),
                            sizeof(file), eof, sizeof(eof), &eof_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, metadata,
                                                metadata_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, first,
                                                first_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, eof, eof_len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_true(entity.receiver.active);
    zassert_equal(capture.count, 2u);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &ops, missing,
                                                missing_len),
                  CCSDS_CFDP_STATUS_OK);

    zassert_false(entity.receiver.active);
    zassert_true(store.dst.exists);
    zassert_equal(store.dst.size, sizeof(file));
    zassert_mem_equal(store.dst.data, file, sizeof(file));
    zassert_equal(store.commit_count, 1u);
    zassert_equal(store.discard_count, 0u);
    zassert_equal(capture.count, 3u);
    zassert_equal(ccsds_cfdp_decode_finished(capture.pdu[2],
                                             capture.pdu_len[2], &finished,
                                             &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(finished.header.transmission_mode,
                  CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED);
    zassert_equal(finished.condition_code, CCSDS_CFDP_CONDITION_NO_ERROR);
    zassert_equal(finished.delivery_code,
                  CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE);
}

ZTEST(ccsds_cfdp_entity, test_acknowledged_sender_recovers_one_dropped_chunk)
{
    ccsds_cfdp_entity_t sender;
    ccsds_cfdp_entity_t receiver;
    struct closure_loopback loopback;
    struct closure_loopback_endpoint sender_endpoint;
    struct closure_loopback_endpoint receiver_endpoint;
    uint8_t file[(2u * CCSDS_CFDP_MAX_SEGMENT_SIZE) + 5u];
    struct memory_filestore source_store = {
        .data = file,
        .size = sizeof(file),
    };
    struct receive_filestore dest_store;
    ccsds_cfdp_filestore_ops_t source_ops =
        memory_filestore_ops(&source_store);
    ccsds_cfdp_filestore_ops_t dest_ops = receive_filestore_ops(&dest_store);
    ccsds_cfdp_ut_ops_t sender_ut;
    ccsds_cfdp_ut_ops_t receiver_ut;
    const ccsds_cfdp_put_request_t request = acknowledged_put_request();
    ccsds_cfdp_transaction_id_t id;

    for (size_t i = 0u; i < sizeof(file); i++) {
        file[i] = (uint8_t)(0x30u + (i & 0x3fu));
    }
    memset(&loopback, 0, sizeof(loopback));
    memset(&sender_endpoint, 0, sizeof(sender_endpoint));
    memset(&receiver_endpoint, 0, sizeof(receiver_endpoint));
    memset(&dest_store, 0, sizeof(dest_store));

    loopback.sender = &sender;
    loopback.receiver = &receiver;
    loopback.source_ops = &source_ops;
    loopback.dest_ops = &dest_ops;
    loopback.sender_endpoint = &sender_endpoint;
    loopback.receiver_endpoint = &receiver_endpoint;
    loopback.drop_filedata_enabled = true;
    loopback.drop_filedata_offset = CCSDS_CFDP_MAX_SEGMENT_SIZE;
    loopback.drop_filedata_once = true;
    sender_endpoint.loopback = &loopback;
    sender_endpoint.local_entity_id = 0x12u;
    receiver_endpoint.loopback = &loopback;
    receiver_endpoint.local_entity_id = 0x34u;
    sender_ut = closure_ut(&sender_endpoint);
    receiver_ut = closure_ut(&receiver_endpoint);

    init_entity_with_custom_ut(&sender, 0x12u, 0x34u, &sender_ut);
    init_entity_with_custom_ut(&receiver, 0x34u, 0x12u, &receiver_ut);

    zassert_equal(ccsds_cfdp_entity_send_file(&sender, &source_ops, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);

    zassert_false(sender.sender.active);
    zassert_false(receiver.receiver.active);
    zassert_true(dest_store.dst.exists);
    zassert_equal(dest_store.dst.size, sizeof(file));
    zassert_mem_equal(dest_store.dst.data, file, sizeof(file));
    zassert_equal(loopback.dropped_count, 1u);
    zassert_equal(loopback.receiver_to_sender_count, 3u);
    zassert_equal(source_store.close_count, 1u);
}

ZTEST(ccsds_cfdp_entity, test_acknowledged_sender_recovers_multiple_dropped_chunks)
{
    ccsds_cfdp_entity_t sender;
    ccsds_cfdp_entity_t receiver;
    struct closure_loopback loopback;
    struct closure_loopback_endpoint sender_endpoint;
    struct closure_loopback_endpoint receiver_endpoint;
    uint8_t file[(3u * CCSDS_CFDP_MAX_SEGMENT_SIZE) + 9u];
    struct memory_filestore source_store = {
        .data = file,
        .size = sizeof(file),
    };
    struct receive_filestore dest_store;
    ccsds_cfdp_filestore_ops_t source_ops =
        memory_filestore_ops(&source_store);
    ccsds_cfdp_filestore_ops_t dest_ops = receive_filestore_ops(&dest_store);
    ccsds_cfdp_ut_ops_t sender_ut;
    ccsds_cfdp_ut_ops_t receiver_ut;
    const ccsds_cfdp_put_request_t request = acknowledged_put_request();
    ccsds_cfdp_transaction_id_t id;

    for (size_t i = 0u; i < sizeof(file); i++) {
        file[i] = (uint8_t)(i & 0xffu);
    }
    memset(&loopback, 0, sizeof(loopback));
    memset(&sender_endpoint, 0, sizeof(sender_endpoint));
    memset(&receiver_endpoint, 0, sizeof(receiver_endpoint));
    memset(&dest_store, 0, sizeof(dest_store));

    loopback.sender = &sender;
    loopback.receiver = &receiver;
    loopback.source_ops = &source_ops;
    loopback.dest_ops = &dest_ops;
    loopback.sender_endpoint = &sender_endpoint;
    loopback.receiver_endpoint = &receiver_endpoint;
    loopback.drop_filedata_enabled = true;
    loopback.drop_filedata_once = true;
    loopback.drop_filedata_offset_count = 2u;
    loopback.drop_filedata_offsets[0] = 0u;
    loopback.drop_filedata_offsets[1] = 2u * CCSDS_CFDP_MAX_SEGMENT_SIZE;
    sender_endpoint.loopback = &loopback;
    sender_endpoint.local_entity_id = 0x12u;
    receiver_endpoint.loopback = &loopback;
    receiver_endpoint.local_entity_id = 0x34u;
    sender_ut = closure_ut(&sender_endpoint);
    receiver_ut = closure_ut(&receiver_endpoint);

    init_entity_with_custom_ut(&sender, 0x12u, 0x34u, &sender_ut);
    init_entity_with_custom_ut(&receiver, 0x34u, 0x12u, &receiver_ut);

    zassert_equal(ccsds_cfdp_entity_send_file(&sender, &source_ops, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);

    zassert_false(sender.sender.active);
    zassert_false(receiver.receiver.active);
    zassert_true(dest_store.dst.exists);
    zassert_equal(dest_store.dst.size, sizeof(file));
    zassert_mem_equal(dest_store.dst.data, file, sizeof(file));
    zassert_equal(loopback.dropped_count, 2u);
    zassert_equal(loopback.drop_filedata_drop_counts[0], 1u);
    zassert_equal(loopback.drop_filedata_drop_counts[1], 1u);
}

ZTEST(ccsds_cfdp_entity, test_acknowledged_sender_invalid_nak_range_fails)
{
    ccsds_cfdp_entity_t entity;
    const uint8_t file[] = { 0u, 1u, 2u, 3u };
    struct memory_filestore source_store = {
        .data = file,
        .size = sizeof(file),
    };
    ccsds_cfdp_filestore_ops_t source_ops =
        memory_filestore_ops(&source_store);
    ccsds_cfdp_transaction_id_t id;
    void *handle = NULL;
    uint32_t file_size = 0u;
    const ccsds_cfdp_nak_range_t range = {
        .start = sizeof(file),
        .end = sizeof(file) + 1u,
    };
    uint8_t nak[CCSDS_CFDP_MAX_PDU_SIZE];
    size_t nak_len;

    init_entity(&entity);
    zassert_equal(ccsds_cfdp_entity_create_sender_transaction(&entity, &id),
                  CCSDS_CFDP_STATUS_OK);
    entity.sender.peer_entity_id = 0x34u;
    entity.sender.transmission_mode =
        CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED;
    entity.sender.file_size = sizeof(file);
    entity.sender.eof_checksum = modular_checksum(file, sizeof(file));
    zassert_equal(source_ops.open_read(source_ops.user, "src.bin", &handle,
                                       &file_size),
                  0);
    zassert_equal(file_size, sizeof(file));
    entity.sender.file_handle_open = true;
    entity.sender.file_handle = handle;

    encode_sender_nak(id.transaction_sequence_number, 0u, sizeof(file) + 1u,
                      &range, 1u, nak, sizeof(nak), &nak_len);

    zassert_equal(ccsds_cfdp_entity_receive_pdu(&entity, &source_ops, nak,
                                                nak_len),
                  CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
    zassert_false(entity.sender.active);
    zassert_equal(source_ops.close(source_ops.user, handle), 0);
}

ZTEST_SUITE(ccsds_cfdp_entity, NULL, NULL, NULL, NULL, NULL);
