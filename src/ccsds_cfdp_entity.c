#include "ccsds_cfdp_entity.h"

#include <string.h>

#include <zephyr/sys/__assert.h>

#define CCSDS_CFDP_MAX_ENCODED_INT_LEN 8u

static bool encoded_int_len_is_valid(uint8_t len, uint8_t max_len)
{
    return len >= 1u && len <= max_len && len <= CCSDS_CFDP_MAX_ENCODED_INT_LEN;
}

static bool value_fits_len(uint64_t value, uint8_t len)
{
    if (len >= CCSDS_CFDP_MAX_ENCODED_INT_LEN) {
        return true;
    }

    return (value >> (len * 8u)) == 0u;
}

static uint64_t transaction_sequence_limit(uint8_t len)
{
    if (len >= CCSDS_CFDP_MAX_ENCODED_INT_LEN) {
        return UINT64_MAX;
    }

    return 1ULL << (len * 8u);
}

static void advance_transaction_sequence_number(ccsds_cfdp_entity_t *entity)
{
    const uint64_t limit =
        transaction_sequence_limit(entity->transaction_sequence_number_len);

    if (limit == UINT64_MAX) {
        entity->next_transaction_sequence_number++;
        return;
    }

    entity->next_transaction_sequence_number =
        (entity->next_transaction_sequence_number + 1u) % limit;
}

static bool transaction_id_matches(const ccsds_cfdp_transaction_id_t *a,
                                   const ccsds_cfdp_transaction_id_t *b)
{
    return a->source_entity_id == b->source_entity_id &&
           a->transaction_sequence_number == b->transaction_sequence_number;
}

static size_t bounded_strlen(const char *str, size_t max_len)
{
    size_t len = 0u;

    while (len <= max_len && str[len] != '\0') {
        len++;
    }

    return len;
}

static bool path_len_is_valid(const char *path, size_t *len)
{
    size_t path_len;

    if (path == NULL) {
        return false;
    }

    path_len = bounded_strlen(path, CCSDS_CFDP_MAX_FILENAME_LEN);
    if (path_len == 0u || path_len > CCSDS_CFDP_MAX_FILENAME_LEN) {
        return false;
    }

    *len = path_len;
    return true;
}

static ccsds_cfdp_pdu_header_t sender_header(
    const ccsds_cfdp_entity_t *entity, enum ccsds_cfdp_pdu_type pdu_type)
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
        .entity_id_len = entity->entity_id_len,
        .transaction_sequence_number_len =
            entity->transaction_sequence_number_len,
        .source_entity_id = entity->sender.id.source_entity_id,
        .transaction_sequence_number =
            entity->sender.id.transaction_sequence_number,
        .destination_entity_id = entity->sender.peer_entity_id,
    };
}

static enum ccsds_cfdp_status
send_encoded_pdu(ccsds_cfdp_entity_t *entity, size_t len)
{
    int rc = entity->ut.send_pdu(entity->ut.user, entity->sender.peer_entity_id,
                                 entity->pdu_buf, len);

    return rc == 0 ? CCSDS_CFDP_STATUS_OK :
                     CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
}

static enum ccsds_cfdp_status
send_encoded_pdu_to(ccsds_cfdp_entity_t *entity, uint64_t dest_entity_id,
                    size_t len)
{
    int rc = entity->ut.send_pdu(entity->ut.user, dest_entity_id,
                                 entity->pdu_buf, len);

    return rc == 0 ? CCSDS_CFDP_STATUS_OK :
                     CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
}

static enum ccsds_cfdp_status
send_metadata(ccsds_cfdp_entity_t *entity,
              const ccsds_cfdp_put_request_t *request, size_t source_len,
              size_t destination_len, uint32_t file_size)
{
    ccsds_cfdp_metadata_pdu_t metadata = {
        .header = sender_header(entity, CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE),
        .closure_requested = request->closure_requested,
        .checksum_type = request->checksum_type,
        .file_size = file_size,
        .source_filename = {
            .value = (const uint8_t *)request->source_path,
            .len = (uint8_t)source_len,
        },
        .destination_filename = {
            .value = (const uint8_t *)request->destination_path,
            .len = (uint8_t)destination_len,
        },
    };
    size_t pdu_len;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_encode_metadata(&metadata, entity->pdu_buf,
                                         sizeof(entity->pdu_buf), &pdu_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    return send_encoded_pdu(entity, pdu_len);
}

static enum ccsds_cfdp_status
send_filedata(ccsds_cfdp_entity_t *entity, uint32_t offset,
              const uint8_t *data, size_t data_len)
{
    ccsds_cfdp_filedata_pdu_t filedata = {
        .header = sender_header(entity, CCSDS_CFDP_PDU_TYPE_FILE_DATA),
        .offset = offset,
        .data = data,
        .data_len = data_len,
    };
    size_t pdu_len;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_encode_filedata(&filedata, entity->pdu_buf,
                                         sizeof(entity->pdu_buf), &pdu_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    return send_encoded_pdu(entity, pdu_len);
}

static enum ccsds_cfdp_status
send_eof(ccsds_cfdp_entity_t *entity, uint32_t checksum, uint32_t file_size)
{
    ccsds_cfdp_eof_pdu_t eof = {
        .header = sender_header(entity, CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .file_checksum = checksum,
        .file_size = file_size,
    };
    size_t pdu_len;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_encode_eof(&eof, entity->pdu_buf,
                                   sizeof(entity->pdu_buf), &pdu_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    return send_encoded_pdu(entity, pdu_len);
}

static bool filestore_is_valid(const ccsds_cfdp_filestore_ops_t *filestore)
{
    return filestore != NULL && filestore->open_read != NULL &&
           filestore->read != NULL && filestore->close != NULL;
}

static bool receive_filestore_is_valid(
    const ccsds_cfdp_filestore_ops_t *filestore)
{
    return filestore != NULL && filestore->open_write_tmp != NULL &&
           filestore->read != NULL && filestore->write != NULL &&
           filestore->close != NULL && filestore->commit_tmp != NULL &&
           filestore->discard_tmp != NULL;
}

static bool incoming_header_is_supported(const ccsds_cfdp_entity_t *entity,
                                         const ccsds_cfdp_pdu_header_t *header)
{
    return header->destination_entity_id == entity->local_entity_id &&
           header->source_entity_id == entity->remote_entity_id &&
           header->entity_id_len == entity->entity_id_len &&
           header->transaction_sequence_number_len ==
               entity->transaction_sequence_number_len &&
           header->direction == CCSDS_CFDP_DIRECTION_TOWARD_RECEIVER &&
           header->transmission_mode ==
               CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED &&
           header->crc_flag == CCSDS_CFDP_CRC_NOT_PRESENT;
}

static bool incoming_finished_header_is_supported(
    const ccsds_cfdp_entity_t *entity, const ccsds_cfdp_pdu_header_t *header)
{
    return header->source_entity_id == entity->local_entity_id &&
           header->destination_entity_id == entity->remote_entity_id &&
           header->entity_id_len == entity->entity_id_len &&
           header->transaction_sequence_number_len ==
               entity->transaction_sequence_number_len &&
           header->direction == CCSDS_CFDP_DIRECTION_TOWARD_SENDER &&
           header->transmission_mode ==
               CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED &&
           header->crc_flag == CCSDS_CFDP_CRC_NOT_PRESENT;
}

static ccsds_cfdp_transaction_id_t transaction_id_from_header(
    const ccsds_cfdp_pdu_header_t *header)
{
    return (ccsds_cfdp_transaction_id_t){
        .source_entity_id = header->source_entity_id,
        .transaction_sequence_number = header->transaction_sequence_number,
    };
}

static enum ccsds_cfdp_status receiver_match_active(
    const ccsds_cfdp_entity_t *entity, const ccsds_cfdp_pdu_header_t *header)
{
    ccsds_cfdp_transaction_id_t incoming = transaction_id_from_header(header);

    if (!entity->receiver.active || !entity->receiver.metadata_received) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    if (!transaction_id_matches(&entity->receiver.id, &incoming)) {
        return CCSDS_CFDP_STATUS_TRANSACTION_BUSY;
    }

    return CCSDS_CFDP_STATUS_OK;
}

struct receiver_checksum_read_ctx {
    const ccsds_cfdp_filestore_ops_t *filestore;
    void *handle;
};

static enum ccsds_cfdp_status receiver_checksum_read(void *user_data,
                                                     uint32_t offset,
                                                     uint8_t *buf, size_t cap,
                                                     size_t *len)
{
    struct receiver_checksum_read_ctx *ctx = user_data;

    if (ctx->filestore->read(ctx->filestore->user, ctx->handle, offset, buf,
                             cap, len) != 0) {
        return CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    }

    return CCSDS_CFDP_STATUS_OK;
}

static enum ccsds_cfdp_status receiver_compute_checksum(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    uint32_t *checksum)
{
    ccsds_cfdp_checksum_state_t state;
    struct receiver_checksum_read_ctx ctx = {
        .filestore = filestore,
        .handle = entity->receiver.file_handle,
    };
    uint32_t offset = 0u;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_checksum_init(&state, entity->receiver.checksum_type);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    while (offset < entity->receiver.file_size) {
        const size_t remaining = (size_t)(entity->receiver.file_size - offset);
        const size_t request_len =
            remaining < sizeof(entity->file_segment_buf) ?
            remaining :
            sizeof(entity->file_segment_buf);
        size_t nread = 0u;

        status = receiver_checksum_read(&ctx, offset, entity->file_segment_buf,
                                        request_len, &nread);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }
        if (nread == 0u || nread > request_len || nread > remaining) {
            return CCSDS_CFDP_STATUS_FILE_SIZE_ERROR;
        }

        status = ccsds_cfdp_checksum_update(&state, offset,
                                            entity->file_segment_buf, nread);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }

        offset += (uint32_t)nread;
    }

    return ccsds_cfdp_checksum_finish(&state, checksum);
}

static enum ccsds_cfdp_status receiver_finish(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    enum ccsds_cfdp_status status)
{
    const bool closure_requested = entity->receiver.closure_requested;
    const uint64_t finished_dest_entity_id = entity->receiver.peer_entity_id;
    enum ccsds_cfdp_status finished_status = CCSDS_CFDP_STATUS_OK;

    if (entity->receiver.file_handle_open &&
        filestore->close(filestore->user, entity->receiver.file_handle) != 0 &&
        status == CCSDS_CFDP_STATUS_OK) {
        status = CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    }
    entity->receiver.file_handle_open = false;
    entity->receiver.file_handle = NULL;

    if (status == CCSDS_CFDP_STATUS_OK) {
        if (filestore->commit_tmp(filestore->user,
                                  entity->receiver.destination_path) != 0) {
            status = CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
        }
    } else {
        (void)filestore->discard_tmp(filestore->user,
                                     entity->receiver.destination_path);
    }

    if (closure_requested) {
        enum ccsds_cfdp_condition_code condition =
            CCSDS_CFDP_CONDITION_NO_ERROR;
        enum ccsds_cfdp_file_status file_status =
            CCSDS_CFDP_FILE_STATUS_RETAINED;
        ccsds_cfdp_finished_pdu_t finished = {
            .header = {
                .version = CCSDS_CFDP_VERSION_1,
                .pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
                .direction = CCSDS_CFDP_DIRECTION_TOWARD_SENDER,
                .transmission_mode =
                    CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED,
                .crc_flag = CCSDS_CFDP_CRC_NOT_PRESENT,
                .file_size_mode = CCSDS_CFDP_FILE_SIZE_SMALL,
                .pdu_data_field_len = 0u,
                .segmentation_control =
                    CCSDS_CFDP_SEGMENTATION_RECORD_BOUNDARIES_NOT_PRESERVED,
                .segment_metadata_present = false,
                .entity_id_len = entity->entity_id_len,
                .transaction_sequence_number_len =
                    entity->transaction_sequence_number_len,
                .source_entity_id = entity->receiver.id.source_entity_id,
                .transaction_sequence_number =
                    entity->receiver.id.transaction_sequence_number,
                .destination_entity_id = entity->local_entity_id,
            },
            .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
            .delivery_code = CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE,
            .file_status = CCSDS_CFDP_FILE_STATUS_RETAINED,
        };
        size_t pdu_len;

        if (status == CCSDS_CFDP_STATUS_FILESTORE_REJECTION) {
            condition = CCSDS_CFDP_CONDITION_FILESTORE_REJECTION;
            file_status = CCSDS_CFDP_FILE_STATUS_DISCARDED_FILESTORE_REJECTION;
        } else if (status == CCSDS_CFDP_STATUS_CHECKSUM_FAILURE) {
            condition = CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE;
            file_status = CCSDS_CFDP_FILE_STATUS_DISCARDED_DELIBERATELY;
        } else if (status == CCSDS_CFDP_STATUS_FILE_SIZE_ERROR) {
            condition = CCSDS_CFDP_CONDITION_FILE_SIZE_ERROR;
            file_status = CCSDS_CFDP_FILE_STATUS_DISCARDED_DELIBERATELY;
        } else if (status != CCSDS_CFDP_STATUS_OK) {
            condition = CCSDS_CFDP_CONDITION_CANCEL_REQUEST_RECEIVED;
            file_status = CCSDS_CFDP_FILE_STATUS_DISCARDED_DELIBERATELY;
        }

        finished.condition_code = condition;
        finished.delivery_code =
            status == CCSDS_CFDP_STATUS_OK ?
            CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE :
            CCSDS_CFDP_DELIVERY_CODE_DATA_INCOMPLETE;
        finished.file_status = file_status;

        finished_status = ccsds_cfdp_encode_finished(
            &finished, entity->pdu_buf, sizeof(entity->pdu_buf), &pdu_len);
        if (finished_status == CCSDS_CFDP_STATUS_OK) {
            finished_status =
                send_encoded_pdu_to(entity, finished_dest_entity_id, pdu_len);
        }
    }

    ccsds_cfdp_entity_release_receiver_transaction(entity);
    if (status == CCSDS_CFDP_STATUS_OK) {
        return finished_status;
    }
    return status;
}

static enum ccsds_cfdp_status receiver_handle_metadata(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_metadata_pdu_t metadata;
    ccsds_cfdp_transaction_id_t incoming;
    size_t consumed;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_decode_metadata(pdu, pdu_len, &metadata, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (consumed != pdu_len ||
        !incoming_header_is_supported(entity, &metadata.header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    incoming = transaction_id_from_header(&metadata.header);
    if (entity->receiver.active) {
        if (!transaction_id_matches(&entity->receiver.id, &incoming)) {
            return CCSDS_CFDP_STATUS_TRANSACTION_BUSY;
        }
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    status = ccsds_cfdp_checksum_init(&entity->receiver.checksum_state,
                                      metadata.checksum_type);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    status = ccsds_cfdp_ranges_init(&entity->receiver.received_ranges);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    memset(entity->receiver.destination_path, 0,
           sizeof(entity->receiver.destination_path));
    memcpy(entity->receiver.destination_path,
           metadata.destination_filename.value, metadata.destination_filename.len);

    if (filestore->open_write_tmp(filestore->user,
                                  entity->receiver.destination_path,
                                  &entity->receiver.file_handle) != 0) {
        memset(&entity->receiver, 0, sizeof(entity->receiver));
        return CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    }

    entity->receiver.active = true;
    entity->receiver.metadata_received = true;
    entity->receiver.file_handle_open = true;
    entity->receiver.id = incoming;
    entity->receiver.peer_entity_id = metadata.header.source_entity_id;
    entity->receiver.file_size = metadata.file_size;
    entity->receiver.checksum_type = metadata.checksum_type;
    entity->receiver.closure_requested = metadata.closure_requested;

    return CCSDS_CFDP_STATUS_OK;
}

static enum ccsds_cfdp_status sender_handle_finished(
    ccsds_cfdp_entity_t *entity, const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_finished_pdu_t finished;
    ccsds_cfdp_transaction_id_t incoming;
    size_t consumed;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_decode_finished(pdu, pdu_len, &finished, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (consumed != pdu_len ||
        !incoming_finished_header_is_supported(entity, &finished.header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    incoming = transaction_id_from_header(&finished.header);
    if (!entity->sender.active ||
        !transaction_id_matches(&entity->sender.id, &incoming)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    entity->sender.finished_received = true;
    if (finished.condition_code == CCSDS_CFDP_CONDITION_NO_ERROR &&
        finished.delivery_code == CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE) {
        entity->sender.finished_status = CCSDS_CFDP_STATUS_OK;
    } else if (finished.condition_code ==
               CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE) {
        entity->sender.finished_status = CCSDS_CFDP_STATUS_CHECKSUM_FAILURE;
    } else if (finished.condition_code ==
               CCSDS_CFDP_CONDITION_FILE_SIZE_ERROR) {
        entity->sender.finished_status = CCSDS_CFDP_STATUS_FILE_SIZE_ERROR;
    } else if (finished.condition_code ==
               CCSDS_CFDP_CONDITION_FILESTORE_REJECTION) {
        entity->sender.finished_status =
            CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    } else {
        entity->sender.finished_status = CCSDS_CFDP_STATUS_CANCEL_REQUEST;
    }

    return entity->sender.finished_status;
}

static enum ccsds_cfdp_status receiver_handle_filedata(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_filedata_pdu_t filedata;
    uint32_t end;
    size_t consumed;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_decode_filedata(pdu, pdu_len, &filedata, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (consumed != pdu_len ||
        !incoming_header_is_supported(entity, &filedata.header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    status = receiver_match_active(entity, &filedata.header);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if (filedata.data_len > UINT32_MAX ||
        filedata.offset > UINT32_MAX - (uint32_t)filedata.data_len) {
        return CCSDS_CFDP_STATUS_FILE_SIZE_ERROR;
    }
    end = filedata.offset + (uint32_t)filedata.data_len;
    if (end > entity->receiver.file_size) {
        return CCSDS_CFDP_STATUS_FILE_SIZE_ERROR;
    }

    if (filestore->write(filestore->user, entity->receiver.file_handle,
                         filedata.offset, filedata.data,
                         filedata.data_len) != 0) {
        return CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    }

    status = ccsds_cfdp_ranges_add(&entity->receiver.received_ranges,
                                   filedata.offset, end);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    return ccsds_cfdp_checksum_update(&entity->receiver.checksum_state,
                                      filedata.offset, filedata.data,
                                      filedata.data_len);
}

static enum ccsds_cfdp_status receiver_handle_eof(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_eof_pdu_t eof;
    size_t consumed;
    enum ccsds_cfdp_status status;
    bool complete = false;
    uint32_t checksum = 0u;

    status = ccsds_cfdp_decode_eof(pdu, pdu_len, &eof, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (consumed != pdu_len ||
        !incoming_header_is_supported(entity, &eof.header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    status = receiver_match_active(entity, &eof.header);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if (eof.condition_code != CCSDS_CFDP_CONDITION_NO_ERROR ||
        eof.file_size != entity->receiver.file_size) {
        return receiver_finish(entity, filestore,
                               CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
    }

    status = ccsds_cfdp_ranges_is_complete(&entity->receiver.received_ranges,
                                           0u, eof.file_size, &complete);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return receiver_finish(entity, filestore, status);
    }
    if (!complete) {
        return receiver_finish(entity, filestore,
                               CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
    }

    status = receiver_compute_checksum(entity, filestore, &checksum);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return receiver_finish(entity, filestore, status);
    }
    if (checksum != eof.file_checksum) {
        return receiver_finish(entity, filestore,
                               CCSDS_CFDP_STATUS_CHECKSUM_FAILURE);
    }

    return receiver_finish(entity, filestore, CCSDS_CFDP_STATUS_OK);
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_init(ccsds_cfdp_entity_t *entity,
                       const ccsds_cfdp_entity_config_t *config,
                       const ccsds_cfdp_ut_ops_t *ut)
{
    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(config != NULL, "CFDP entity config is NULL");
    __ASSERT(ut != NULL, "CFDP UT ops are NULL");

    if (!encoded_int_len_is_valid(config->entity_id_len,
                                  CCSDS_CFDP_MAX_ENTITY_ID_LEN) ||
        !encoded_int_len_is_valid(config->transaction_sequence_number_len,
                                  CCSDS_CFDP_MAX_TRANS_SEQ_LEN) ||
        !value_fits_len(config->local_entity_id, config->entity_id_len) ||
        !value_fits_len(config->remote_entity_id, config->entity_id_len) ||
        !value_fits_len(config->initial_transaction_sequence_number,
                        config->transaction_sequence_number_len) ||
        ut->send_pdu == NULL) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    memset(entity, 0, sizeof(*entity));
    entity->local_entity_id = config->local_entity_id;
    entity->remote_entity_id = config->remote_entity_id;
    entity->entity_id_len = config->entity_id_len;
    entity->transaction_sequence_number_len =
        config->transaction_sequence_number_len;
    entity->next_transaction_sequence_number =
        config->initial_transaction_sequence_number;
    entity->ut = *ut;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_create_sender_transaction(
    ccsds_cfdp_entity_t *entity, ccsds_cfdp_transaction_id_t *transaction_id)
{
    ccsds_cfdp_transaction_id_t allocated;

    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(transaction_id != NULL, "CFDP transaction ID output is NULL");

    if (entity->sender.active) {
        return CCSDS_CFDP_STATUS_TRANSACTION_BUSY;
    }

    allocated.source_entity_id = entity->local_entity_id;
    allocated.transaction_sequence_number =
        entity->next_transaction_sequence_number;
    advance_transaction_sequence_number(entity);

    entity->sender.active = true;
    entity->sender.id = allocated;
    entity->sender.peer_entity_id = entity->remote_entity_id;
    entity->sender.finished_status = CCSDS_CFDP_STATUS_OK;
    *transaction_id = allocated;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_send_file(ccsds_cfdp_entity_t *entity,
                            const ccsds_cfdp_filestore_ops_t *filestore,
                            const ccsds_cfdp_put_request_t *request,
                            ccsds_cfdp_transaction_id_t *transaction_id)
{
    ccsds_cfdp_transaction_id_t allocated;
    ccsds_cfdp_checksum_state_t checksum_state;
    void *handle = NULL;
    uint32_t file_size = 0u;
    uint32_t offset = 0u;
    uint32_t checksum = 0u;
    size_t source_len;
    size_t destination_len;
    enum ccsds_cfdp_status status;
    bool handle_open = false;

    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(filestore != NULL, "CFDP filestore ops are NULL");
    __ASSERT(request != NULL, "CFDP put request is NULL");
    __ASSERT(transaction_id != NULL, "CFDP transaction ID output is NULL");

    if (!filestore_is_valid(filestore) ||
        !path_len_is_valid(request->source_path, &source_len) ||
        !path_len_is_valid(request->destination_path, &destination_len)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    status = ccsds_cfdp_checksum_init(&checksum_state, request->checksum_type);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    status = ccsds_cfdp_entity_create_sender_transaction(entity, &allocated);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    entity->sender.closure_requested = request->closure_requested;
    *transaction_id = allocated;

    if (filestore->open_read(filestore->user, request->source_path, &handle,
                             &file_size) != 0) {
        status = CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
        goto out_release;
    }
    if (handle == NULL && file_size > 0u) {
        status = CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
        goto out_release;
    }
    handle_open = true;

    status = send_metadata(entity, request, source_len, destination_len,
                           file_size);
    if (status != CCSDS_CFDP_STATUS_OK) {
        goto out_release;
    }

    while (offset < file_size) {
        const size_t remaining = (size_t)(file_size - offset);
        const size_t request_len =
            remaining < sizeof(entity->file_segment_buf) ?
            remaining :
            sizeof(entity->file_segment_buf);
        size_t nread = 0u;

        if (filestore->read(filestore->user, handle, offset,
                            entity->file_segment_buf, request_len,
                            &nread) != 0) {
            status = CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
            goto out_release;
        }
        if (nread == 0u || nread > request_len || nread > remaining) {
            status = CCSDS_CFDP_STATUS_FILE_SIZE_ERROR;
            goto out_release;
        }

        status = send_filedata(entity, offset, entity->file_segment_buf,
                               nread);
        if (status != CCSDS_CFDP_STATUS_OK) {
            goto out_release;
        }

        status = ccsds_cfdp_checksum_update(&checksum_state, offset,
                                            entity->file_segment_buf, nread);
        if (status != CCSDS_CFDP_STATUS_OK) {
            goto out_release;
        }

        offset += (uint32_t)nread;
    }

    status = ccsds_cfdp_checksum_finish(&checksum_state, &checksum);
    if (status != CCSDS_CFDP_STATUS_OK) {
        goto out_release;
    }

    status = send_eof(entity, checksum, file_size);
    if (status == CCSDS_CFDP_STATUS_OK && request->closure_requested &&
        entity->sender.finished_received) {
        status = entity->sender.finished_status;
    } else if (status == CCSDS_CFDP_STATUS_OK && request->closure_requested &&
               entity->ut.now_ms != NULL) {
        status = CCSDS_CFDP_STATUS_INACTIVITY_DETECTED;
    }

out_release:
    if (handle_open && filestore->close(filestore->user, handle) != 0 &&
        status == CCSDS_CFDP_STATUS_OK) {
        status = CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    }
    ccsds_cfdp_entity_release_sender_transaction(entity);
    return status;
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_receive_pdu(ccsds_cfdp_entity_t *entity,
                              const ccsds_cfdp_filestore_ops_t *filestore,
                              const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_pdu_header_t header;
    size_t header_len;
    enum ccsds_cfdp_status status;
    uint8_t directive;

    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(pdu != NULL, "CFDP incoming PDU is NULL");

    status = ccsds_cfdp_decode_header(pdu, pdu_len, &header, &header_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if (header.direction == CCSDS_CFDP_DIRECTION_TOWARD_SENDER) {
        if (!incoming_finished_header_is_supported(entity, &header) ||
            header.pdu_type != CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE ||
            header.pdu_data_field_len == 0u || pdu_len <= header_len) {
            return CCSDS_CFDP_STATUS_UNSUPPORTED;
        }

        directive = pdu[header_len];
        if (directive != CCSDS_CFDP_DIRECTIVE_FINISHED) {
            return CCSDS_CFDP_STATUS_UNSUPPORTED;
        }
        return sender_handle_finished(entity, pdu, pdu_len);
    }

    if (!incoming_header_is_supported(entity, &header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }
    if (!receive_filestore_is_valid(filestore)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    if (header.pdu_type == CCSDS_CFDP_PDU_TYPE_FILE_DATA) {
        return receiver_handle_filedata(entity, filestore, pdu, pdu_len);
    }

    if (header.pdu_data_field_len == 0u || pdu_len <= header_len) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    directive = pdu[header_len];
    switch (directive) {
    case CCSDS_CFDP_DIRECTIVE_METADATA:
        return receiver_handle_metadata(entity, filestore, pdu, pdu_len);
    case CCSDS_CFDP_DIRECTIVE_EOF:
        return receiver_handle_eof(entity, filestore, pdu, pdu_len);
    default:
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_match_or_create_receiver_transaction(
    ccsds_cfdp_entity_t *entity, const uint8_t *pdu, size_t pdu_len,
    ccsds_cfdp_transaction_id_t *transaction_id)
{
    ccsds_cfdp_pdu_header_t header;
    ccsds_cfdp_transaction_id_t incoming;
    size_t consumed;
    enum ccsds_cfdp_status status;

    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(pdu != NULL, "CFDP incoming PDU is NULL");
    __ASSERT(transaction_id != NULL, "CFDP transaction ID output is NULL");

    status = ccsds_cfdp_decode_header(pdu, pdu_len, &header, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if (header.destination_entity_id != entity->local_entity_id ||
        header.source_entity_id != entity->remote_entity_id ||
        header.entity_id_len != entity->entity_id_len ||
        header.transaction_sequence_number_len !=
            entity->transaction_sequence_number_len ||
        header.direction != CCSDS_CFDP_DIRECTION_TOWARD_RECEIVER) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    incoming.source_entity_id = header.source_entity_id;
    incoming.transaction_sequence_number = header.transaction_sequence_number;

    if (entity->receiver.active) {
        if (!transaction_id_matches(&entity->receiver.id, &incoming)) {
            return CCSDS_CFDP_STATUS_TRANSACTION_BUSY;
        }

        *transaction_id = entity->receiver.id;
        return CCSDS_CFDP_STATUS_OK;
    }

    entity->receiver.active = true;
    entity->receiver.id = incoming;
    entity->receiver.peer_entity_id = header.source_entity_id;
    *transaction_id = incoming;

    return CCSDS_CFDP_STATUS_OK;
}

void ccsds_cfdp_entity_release_sender_transaction(ccsds_cfdp_entity_t *entity)
{
    __ASSERT(entity != NULL, "CFDP entity is NULL");

    memset(&entity->sender, 0, sizeof(entity->sender));
}

void ccsds_cfdp_entity_release_receiver_transaction(ccsds_cfdp_entity_t *entity)
{
    __ASSERT(entity != NULL, "CFDP entity is NULL");

    memset(&entity->receiver, 0, sizeof(entity->receiver));
}
