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

static void emit_event(ccsds_cfdp_entity_t *entity,
                       ccsds_cfdp_event_type_t type,
                       const ccsds_cfdp_transaction_id_t *id,
                       enum ccsds_cfdp_status status)
{
    if (entity->event_cb == NULL) {
        return;
    }

    const ccsds_cfdp_event_t event = {
        .type = type,
        .transaction_id = *id,
        .status = status,
    };

    entity->event_cb(entity->event_user, &event);
}

static void emit_terminal_event(ccsds_cfdp_entity_t *entity,
                                const ccsds_cfdp_transaction_id_t *id,
                                enum ccsds_cfdp_status status)
{
    emit_event(entity,
               status == CCSDS_CFDP_STATUS_OK ? CCSDS_CFDP_EVENT_COMPLETE :
                                                CCSDS_CFDP_EVENT_FAILED,
               id, status);
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
        .transmission_mode = entity->sender.transmission_mode,
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
           header->transmission_mode <=
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
           header->transmission_mode <=
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

static bool sender_active_matches_header(const ccsds_cfdp_entity_t *entity,
                                         const ccsds_cfdp_pdu_header_t *header)
{
    const ccsds_cfdp_transaction_id_t incoming =
        transaction_id_from_header(header);

    return entity->sender.active &&
           transaction_id_matches(&entity->sender.id, &incoming);
}

static bool receiver_active_matches_header(
    const ccsds_cfdp_entity_t *entity, const ccsds_cfdp_pdu_header_t *header)
{
    const ccsds_cfdp_transaction_id_t incoming =
        transaction_id_from_header(header);

    return entity->receiver.active &&
           transaction_id_matches(&entity->receiver.id, &incoming);
}

static ccsds_cfdp_pdu_header_t receiver_response_header(
    const ccsds_cfdp_entity_t *entity)
{
    return (ccsds_cfdp_pdu_header_t){
        .version = CCSDS_CFDP_VERSION_1,
        .pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
        .direction = CCSDS_CFDP_DIRECTION_TOWARD_SENDER,
        .transmission_mode = entity->receiver.transmission_mode,
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

static enum ccsds_cfdp_status
receiver_verify_complete_file(ccsds_cfdp_entity_t *entity,
                              const ccsds_cfdp_filestore_ops_t *filestore,
                              uint32_t expected_checksum)
{
    enum ccsds_cfdp_status status;
    uint32_t checksum = 0u;

    status = receiver_compute_checksum(entity, filestore, &checksum);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (checksum != expected_checksum) {
        return CCSDS_CFDP_STATUS_CHECKSUM_FAILURE;
    }

    return CCSDS_CFDP_STATUS_OK;
}

static enum ccsds_cfdp_status send_ack_eof(ccsds_cfdp_entity_t *entity,
                                           enum ccsds_cfdp_condition_code code)
{
    ccsds_cfdp_ack_pdu_t ack = {
        .header = receiver_response_header(entity),
        .acknowledged_directive = CCSDS_CFDP_DIRECTIVE_EOF,
        .directive_subtype = CCSDS_CFDP_ACK_DIRECTIVE_SUBTYPE_OTHER,
        .condition_code = code,
        .transaction_status = CCSDS_CFDP_TRANSACTION_STATUS_ACTIVE,
    };
    size_t pdu_len;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_encode_ack(&ack, entity->pdu_buf,
                                   sizeof(entity->pdu_buf), &pdu_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    return send_encoded_pdu_to(entity, entity->receiver.peer_entity_id,
                               pdu_len);
}

static enum ccsds_cfdp_status
send_ack_finished(ccsds_cfdp_entity_t *entity,
                  enum ccsds_cfdp_condition_code code)
{
    ccsds_cfdp_ack_pdu_t ack = {
        .header = sender_header(entity, CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE),
        .acknowledged_directive = CCSDS_CFDP_DIRECTIVE_FINISHED,
        .directive_subtype = CCSDS_CFDP_ACK_DIRECTIVE_SUBTYPE_FINISHED,
        .condition_code = code,
        .transaction_status = CCSDS_CFDP_TRANSACTION_STATUS_TERMINATED,
    };
    size_t pdu_len;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_encode_ack(&ack, entity->pdu_buf,
                                   sizeof(entity->pdu_buf), &pdu_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    return send_encoded_pdu(entity, pdu_len);
}

static enum ccsds_cfdp_status
send_nak_for_missing_ranges(ccsds_cfdp_entity_t *entity)
{
    ccsds_cfdp_ranges_t missing;
    ccsds_cfdp_nak_pdu_t nak = {
        .header = receiver_response_header(entity),
        .scope_start = 0u,
        .scope_end = entity->receiver.file_size,
        .range_count = 0u,
    };
    size_t pdu_len;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_ranges_missing(&entity->receiver.received_ranges, 0u,
                                       entity->receiver.file_size, &missing);
    if (status == CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL) {
        return CCSDS_CFDP_STATUS_NAK_LIMIT_REACHED;
    }
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    nak.range_count = missing.count;
    for (size_t i = 0u; i < missing.count; i++) {
        nak.ranges[i].start = missing.ranges[i].start;
        nak.ranges[i].end = missing.ranges[i].end;
    }

    status = ccsds_cfdp_encode_nak(&nak, entity->pdu_buf,
                                   sizeof(entity->pdu_buf), &pdu_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    return send_encoded_pdu_to(entity, entity->receiver.peer_entity_id,
                               pdu_len);
}

static uint64_t entity_now_ms(const ccsds_cfdp_entity_t *entity)
{
    if (entity->ut.now_ms == NULL) {
        return 0u;
    }

    return entity->ut.now_ms(entity->ut.user);
}

static void arm_retry(ccsds_cfdp_transaction_slot_t *slot, uint64_t now_ms)
{
    slot->retry_deadline_ms = now_ms + CCSDS_CFDP_RETRY_INTERVAL_MS;
}

static bool retry_due(const ccsds_cfdp_transaction_slot_t *slot,
                      uint64_t now_ms)
{
    return slot->retry_deadline_ms == 0u ||
           now_ms >= slot->retry_deadline_ms;
}

static enum ccsds_cfdp_condition_code
finished_condition_from_status(enum ccsds_cfdp_status status)
{
    if (status == CCSDS_CFDP_STATUS_FILESTORE_REJECTION) {
        return CCSDS_CFDP_CONDITION_FILESTORE_REJECTION;
    }
    if (status == CCSDS_CFDP_STATUS_CHECKSUM_FAILURE) {
        return CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE;
    }
    if (status == CCSDS_CFDP_STATUS_FILE_SIZE_ERROR) {
        return CCSDS_CFDP_CONDITION_FILE_SIZE_ERROR;
    }
    if (status == CCSDS_CFDP_STATUS_NAK_LIMIT_REACHED) {
        return CCSDS_CFDP_CONDITION_NAK_LIMIT_REACHED;
    }
    if (status == CCSDS_CFDP_STATUS_OK) {
        return CCSDS_CFDP_CONDITION_NO_ERROR;
    }

    return CCSDS_CFDP_CONDITION_CANCEL_REQUEST_RECEIVED;
}

static enum ccsds_cfdp_file_status
finished_file_status_from_status(enum ccsds_cfdp_status status)
{
    if (status == CCSDS_CFDP_STATUS_OK) {
        return CCSDS_CFDP_FILE_STATUS_RETAINED;
    }
    if (status == CCSDS_CFDP_STATUS_FILESTORE_REJECTION) {
        return CCSDS_CFDP_FILE_STATUS_DISCARDED_FILESTORE_REJECTION;
    }

    return CCSDS_CFDP_FILE_STATUS_DISCARDED_DELIBERATELY;
}

static enum ccsds_cfdp_status
send_finished_for_receiver_status(ccsds_cfdp_entity_t *entity,
                                  enum ccsds_cfdp_status status)
{
    ccsds_cfdp_finished_pdu_t finished = {
        .header = receiver_response_header(entity),
        .condition_code = finished_condition_from_status(status),
        .delivery_code =
            status == CCSDS_CFDP_STATUS_OK ?
            CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE :
            CCSDS_CFDP_DELIVERY_CODE_DATA_INCOMPLETE,
        .file_status = finished_file_status_from_status(status),
    };
    size_t pdu_len;
    enum ccsds_cfdp_status finished_status;

    finished_status = ccsds_cfdp_encode_finished(
        &finished, entity->pdu_buf, sizeof(entity->pdu_buf), &pdu_len);
    if (finished_status != CCSDS_CFDP_STATUS_OK) {
        return finished_status;
    }

    return send_encoded_pdu_to(entity, entity->receiver.peer_entity_id,
                               pdu_len);
}

static void close_sender_handle(ccsds_cfdp_entity_t *entity)
{
    if (entity->sender.file_handle_open &&
        entity->sender.filestore != NULL &&
        entity->sender.filestore->close != NULL) {
        (void)entity->sender.filestore->close(entity->sender.filestore->user,
                                              entity->sender.file_handle);
    }

    entity->sender.file_handle_open = false;
    entity->sender.file_handle = NULL;
}

static void close_discard_receiver(ccsds_cfdp_entity_t *entity)
{
    if (entity->receiver.filestore == NULL) {
        return;
    }

    if (entity->receiver.file_handle_open &&
        entity->receiver.filestore->close != NULL) {
        (void)entity->receiver.filestore->close(
            entity->receiver.filestore->user, entity->receiver.file_handle);
    }
    entity->receiver.file_handle_open = false;
    entity->receiver.file_handle = NULL;

    if (entity->receiver.filestore->discard_tmp != NULL) {
        (void)entity->receiver.filestore->discard_tmp(
            entity->receiver.filestore->user,
            entity->receiver.destination_path);
    }
}

static void release_sender_terminal(ccsds_cfdp_entity_t *entity,
                                    enum ccsds_cfdp_status status)
{
    ccsds_cfdp_transaction_id_t id = entity->sender.id;

    emit_terminal_event(entity, &id, status);
    ccsds_cfdp_entity_release_sender_transaction(entity);
}

static void release_receiver_terminal(ccsds_cfdp_entity_t *entity,
                                      enum ccsds_cfdp_status status)
{
    ccsds_cfdp_transaction_id_t id = entity->receiver.id;

    emit_terminal_event(entity, &id, status);
    ccsds_cfdp_entity_release_receiver_transaction(entity);
}

static void fail_receiver_active_transaction(ccsds_cfdp_entity_t *entity,
                                             enum ccsds_cfdp_status status)
{
    if (!entity->receiver.waiting_for_finished_ack) {
        close_discard_receiver(entity);
    }

    release_receiver_terminal(entity, status);
}

static enum ccsds_cfdp_status receiver_finish(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    enum ccsds_cfdp_status status)
{
    const bool closure_requested = entity->receiver.closure_requested;
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
        entity->receiver.finished_status = status;
        finished_status = send_finished_for_receiver_status(entity, status);
        if (!entity->receiver.active) {
            if (status == CCSDS_CFDP_STATUS_OK) {
                return finished_status;
            }
            return status;
        }
    }

    if (entity->receiver.transmission_mode ==
        CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
        if (finished_status == CCSDS_CFDP_STATUS_OK) {
            entity->receiver.recovery_pending = false;
            entity->receiver.waiting_for_finished_ack = true;
            entity->receiver.retry_count = 0u;
            arm_retry(&entity->receiver, entity_now_ms(entity));
            return status;
        }

        release_receiver_terminal(entity, finished_status);
        if (status == CCSDS_CFDP_STATUS_OK) {
            return finished_status;
        }
        return status;
    }

    release_receiver_terminal(entity, status == CCSDS_CFDP_STATUS_OK ?
                                          finished_status :
                                          status);
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
    memset(entity->receiver.source_path, 0,
           sizeof(entity->receiver.source_path));
    memcpy(entity->receiver.source_path, metadata.source_filename.value,
           metadata.source_filename.len);
    memcpy(entity->receiver.destination_path,
           metadata.destination_filename.value, metadata.destination_filename.len);

    entity->receiver.active = true;
    entity->receiver.metadata_received = true;
    entity->receiver.filestore = filestore;
    entity->receiver.id = incoming;
    entity->receiver.peer_entity_id = metadata.header.source_entity_id;
    entity->receiver.file_size = metadata.file_size;
    entity->receiver.checksum_type = metadata.checksum_type;
    entity->receiver.transmission_mode = metadata.header.transmission_mode;
    entity->receiver.closure_requested =
        metadata.closure_requested ||
        metadata.header.transmission_mode ==
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED;

    if (filestore->open_write_tmp(filestore->user,
                                  entity->receiver.destination_path,
                                  &entity->receiver.file_handle) != 0) {
        emit_terminal_event(entity, &incoming,
                            CCSDS_CFDP_STATUS_FILESTORE_REJECTION);
        memset(&entity->receiver, 0, sizeof(entity->receiver));
        return CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    }

    entity->receiver.file_handle_open = true;

    return CCSDS_CFDP_STATUS_OK;
}

static enum ccsds_cfdp_status sender_fail(ccsds_cfdp_entity_t *entity,
                                          enum ccsds_cfdp_status status);

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
    entity->sender_completion_available = true;
    entity->sender_completion_status = entity->sender.finished_status;

    if (entity->sender.transmission_mode ==
        CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
        enum ccsds_cfdp_status finished_status =
            entity->sender.finished_status;

        status = send_ack_finished(entity, finished.condition_code);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return sender_fail(entity, status);
        }

        release_sender_terminal(entity, finished_status);
        return finished_status;
    }

    return entity->sender.finished_status;
}

static enum ccsds_cfdp_status sender_handle_ack(
    ccsds_cfdp_entity_t *entity, const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_ack_pdu_t ack;
    ccsds_cfdp_transaction_id_t incoming;
    size_t consumed;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_decode_ack(pdu, pdu_len, &ack, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (consumed != pdu_len ||
        !incoming_finished_header_is_supported(entity, &ack.header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }
    if (ack.acknowledged_directive != CCSDS_CFDP_DIRECTIVE_EOF ||
        ack.directive_subtype != CCSDS_CFDP_ACK_DIRECTIVE_SUBTYPE_OTHER ||
        ack.header.transmission_mode !=
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    incoming = transaction_id_from_header(&ack.header);
    if (!entity->sender.active ||
        !transaction_id_matches(&entity->sender.id, &incoming)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    return CCSDS_CFDP_STATUS_OK;
}

static bool sender_nak_header_is_supported(
    const ccsds_cfdp_entity_t *entity, const ccsds_cfdp_pdu_header_t *header)
{
    return incoming_finished_header_is_supported(entity, header) &&
           header->transmission_mode ==
               CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED;
}

static enum ccsds_cfdp_status sender_fail(ccsds_cfdp_entity_t *entity,
                                          enum ccsds_cfdp_status status)
{
    entity->sender.finished_status = status;
    close_sender_handle(entity);
    release_sender_terminal(entity, status);
    return status;
}

static enum ccsds_cfdp_status sender_retransmit_range(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    uint32_t start, uint32_t end)
{
    uint32_t offset = start;

    while (offset < end) {
        const size_t remaining = (size_t)(end - offset);
        const size_t request_len =
            remaining < sizeof(entity->file_segment_buf) ?
            remaining :
            sizeof(entity->file_segment_buf);
        size_t nread = 0u;
        enum ccsds_cfdp_status status;

        if (filestore->read(filestore->user, entity->sender.file_handle,
                            offset, entity->file_segment_buf, request_len,
                            &nread) != 0) {
            return CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
        }
        if (nread == 0u || nread > request_len || nread > remaining) {
            return CCSDS_CFDP_STATUS_FILE_SIZE_ERROR;
        }

        status = send_filedata(entity, offset, entity->file_segment_buf,
                               nread);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }

        offset += (uint32_t)nread;
    }

    return CCSDS_CFDP_STATUS_OK;
}

static enum ccsds_cfdp_status sender_handle_nak(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_nak_pdu_t nak;
    ccsds_cfdp_transaction_id_t incoming;
    size_t consumed;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_decode_nak(pdu, pdu_len, &nak, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (consumed != pdu_len || !sender_nak_header_is_supported(entity,
                                                               &nak.header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    incoming = transaction_id_from_header(&nak.header);
    if (!entity->sender.active ||
        !transaction_id_matches(&entity->sender.id, &incoming)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }
    if (!filestore_is_valid(filestore) || !entity->sender.file_handle_open ||
        entity->sender.file_handle == NULL) {
        return sender_fail(entity, CCSDS_CFDP_STATUS_FILESTORE_REJECTION);
    }
    if (entity->sender.transmission_mode !=
        CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
        return sender_fail(entity, CCSDS_CFDP_STATUS_INVALID_TRANSMISSION_MODE);
    }

    entity->sender.nak_retry_count++;
    if (entity->sender.nak_retry_count > CCSDS_CFDP_MAX_NAK_ROUNDS) {
        return sender_fail(entity, CCSDS_CFDP_STATUS_NAK_LIMIT_REACHED);
    }

    if (nak.scope_start != 0u || nak.scope_end != entity->sender.file_size) {
        return sender_fail(entity, CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
    }

    for (size_t i = 0u; i < nak.range_count; i++) {
        if (nak.ranges[i].end > entity->sender.file_size) {
            return sender_fail(entity, CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
        }

        status = sender_retransmit_range(entity, filestore,
                                         nak.ranges[i].start,
                                         nak.ranges[i].end);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return sender_fail(entity, status);
        }
    }

    status = send_eof(entity, entity->sender.eof_checksum,
                      entity->sender.file_size);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return sender_fail(entity, status);
    }

    return CCSDS_CFDP_STATUS_OK;
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

    status = ccsds_cfdp_checksum_update(&entity->receiver.checksum_state,
                                        filedata.offset, filedata.data,
                                        filedata.data_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if (entity->receiver.eof_received &&
        entity->receiver.transmission_mode ==
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
        bool complete = false;

        status = ccsds_cfdp_ranges_is_complete(
            &entity->receiver.received_ranges, 0u, entity->receiver.file_size,
            &complete);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return receiver_finish(entity, filestore, status);
        }
        if (complete) {
            status = receiver_verify_complete_file(
                entity, filestore, entity->receiver.eof_checksum);
            return receiver_finish(entity, filestore, status);
        }
    }

    return CCSDS_CFDP_STATUS_OK;
}

static enum ccsds_cfdp_status receiver_handle_eof(
    ccsds_cfdp_entity_t *entity, const ccsds_cfdp_filestore_ops_t *filestore,
    const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_eof_pdu_t eof;
    size_t consumed;
    enum ccsds_cfdp_status status;
    bool complete = false;

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

    entity->receiver.eof_checksum = eof.file_checksum;

    if (eof.condition_code != CCSDS_CFDP_CONDITION_NO_ERROR ||
        eof.file_size != entity->receiver.file_size) {
        if (entity->receiver.transmission_mode ==
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
            (void)send_ack_eof(entity, eof.condition_code);
        }
        return receiver_finish(entity, filestore,
                               CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
    }

    if (entity->receiver.transmission_mode ==
        CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
        status = send_ack_eof(entity, eof.condition_code);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }
    }

    status = ccsds_cfdp_ranges_is_complete(&entity->receiver.received_ranges,
                                           0u, eof.file_size, &complete);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return receiver_finish(entity, filestore, status);
    }
    if (!complete) {
        if (entity->receiver.transmission_mode ==
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
            entity->receiver.eof_received = true;
            entity->receiver.eof_checksum = eof.file_checksum;
            status = send_nak_for_missing_ranges(entity);
            if (status != CCSDS_CFDP_STATUS_OK) {
                return receiver_finish(entity, filestore, status);
            }
            entity->receiver.recovery_pending = true;
            entity->receiver.retry_count = 0u;
            arm_retry(&entity->receiver, entity_now_ms(entity));
            return CCSDS_CFDP_STATUS_OK;
        }
        return receiver_finish(entity, filestore,
                               CCSDS_CFDP_STATUS_FILE_SIZE_ERROR);
    }

    status = receiver_verify_complete_file(entity, filestore,
                                           eof.file_checksum);

    return receiver_finish(entity, filestore, status);
}

static enum ccsds_cfdp_status receiver_handle_ack(
    ccsds_cfdp_entity_t *entity, const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_ack_pdu_t ack;
    ccsds_cfdp_transaction_id_t incoming;
    size_t consumed;
    enum ccsds_cfdp_status status;

    status = ccsds_cfdp_decode_ack(pdu, pdu_len, &ack, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (consumed != pdu_len || !incoming_header_is_supported(entity,
                                                             &ack.header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }
    if (ack.acknowledged_directive != CCSDS_CFDP_DIRECTIVE_FINISHED ||
        ack.directive_subtype != CCSDS_CFDP_ACK_DIRECTIVE_SUBTYPE_FINISHED ||
        ack.header.transmission_mode !=
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    incoming = transaction_id_from_header(&ack.header);
    if (!entity->receiver.active ||
        !transaction_id_matches(&entity->receiver.id, &incoming)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    release_receiver_terminal(entity, entity->receiver.finished_status);
    return CCSDS_CFDP_STATUS_OK;
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
    entity->event_cb = config->event_cb;
    entity->event_user = config->event_user;

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
    entity->sender.transmission_mode =
        CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED;
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
    bool keep_sender_active = false;

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
    entity->sender_completion_available = false;
    entity->sender_completion_status = CCSDS_CFDP_STATUS_OK;
    entity->sender.closure_requested = request->closure_requested;
    entity->sender.transmission_mode =
        request->acknowledged_mode ?
        CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED :
        CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED;
    memset(entity->sender.source_path, 0, sizeof(entity->sender.source_path));
    memset(entity->sender.destination_path, 0,
           sizeof(entity->sender.destination_path));
    memcpy(entity->sender.source_path, request->source_path, source_len);
    memcpy(entity->sender.destination_path, request->destination_path,
           destination_len);
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
    entity->sender.file_handle_open = true;
    entity->sender.file_handle = handle;
    entity->sender.filestore = filestore;
    entity->sender.file_size = file_size;
    entity->sender.checksum_type = request->checksum_type;

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
    entity->sender.eof_checksum = checksum;

    status = send_eof(entity, checksum, file_size);
    if (status == CCSDS_CFDP_STATUS_OK && request->acknowledged_mode &&
        entity->sender.active && !entity->sender.finished_received) {
        entity->sender.retry_count = 0u;
        arm_retry(&entity->sender, entity_now_ms(entity));
        keep_sender_active = true;
    } else if (status == CCSDS_CFDP_STATUS_OK && request->closure_requested &&
        entity->sender_completion_available) {
        status = entity->sender_completion_status;
    } else if (status == CCSDS_CFDP_STATUS_OK && request->closure_requested &&
        entity->sender.finished_received) {
        status = entity->sender.finished_status;
    } else if (status == CCSDS_CFDP_STATUS_OK && request->closure_requested &&
               entity->ut.now_ms != NULL) {
        status = CCSDS_CFDP_STATUS_INACTIVITY_DETECTED;
    }

out_release:
    if (keep_sender_active) {
        return status;
    }
    if (handle_open && entity->sender.file_handle_open) {
        close_sender_handle(entity);
    }
    if (entity->sender.active) {
        release_sender_terminal(entity, status);
    }
    entity->sender_completion_available = false;
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
        switch (directive) {
        case CCSDS_CFDP_DIRECTIVE_FINISHED:
            status = sender_handle_finished(entity, pdu, pdu_len);
            break;
        case CCSDS_CFDP_DIRECTIVE_ACK:
            status = sender_handle_ack(entity, pdu, pdu_len);
            break;
        case CCSDS_CFDP_DIRECTIVE_NAK:
            status = sender_handle_nak(entity, filestore, pdu, pdu_len);
            break;
        default:
            status = CCSDS_CFDP_STATUS_UNSUPPORTED;
            break;
        }

        if (status != CCSDS_CFDP_STATUS_OK &&
            sender_active_matches_header(entity, &header)) {
            release_sender_terminal(entity, status);
        }
        return status;
    }

    if (!incoming_header_is_supported(entity, &header)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }
    if (!receive_filestore_is_valid(filestore)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    if (header.pdu_type == CCSDS_CFDP_PDU_TYPE_FILE_DATA) {
        status = receiver_handle_filedata(entity, filestore, pdu, pdu_len);
        if (status != CCSDS_CFDP_STATUS_OK &&
            receiver_active_matches_header(entity, &header)) {
            fail_receiver_active_transaction(entity, status);
        }
        return status;
    }

    if (header.pdu_data_field_len == 0u || pdu_len <= header_len) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    directive = pdu[header_len];
    switch (directive) {
    case CCSDS_CFDP_DIRECTIVE_METADATA:
        status = receiver_handle_metadata(entity, filestore, pdu, pdu_len);
        break;
    case CCSDS_CFDP_DIRECTIVE_EOF:
        status = receiver_handle_eof(entity, filestore, pdu, pdu_len);
        break;
    case CCSDS_CFDP_DIRECTIVE_ACK:
        status = receiver_handle_ack(entity, pdu, pdu_len);
        break;
    default:
        status = CCSDS_CFDP_STATUS_UNSUPPORTED;
        break;
    }

    if (status != CCSDS_CFDP_STATUS_OK &&
        receiver_active_matches_header(entity, &header)) {
        fail_receiver_active_transaction(entity, status);
    }
    return status;
}

void ccsds_cfdp_entity_poll(ccsds_cfdp_entity_t *entity, uint64_t now_ms)
{
    enum ccsds_cfdp_status status;

    __ASSERT(entity != NULL, "CFDP entity is NULL");

    if (entity->receiver.active &&
        entity->receiver.transmission_mode ==
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED &&
        entity->receiver.recovery_pending &&
        retry_due(&entity->receiver, now_ms)) {
        if (entity->receiver.retry_count >= CCSDS_CFDP_MAX_NAK_ROUNDS) {
            close_discard_receiver(entity);
            release_receiver_terminal(
                entity, CCSDS_CFDP_STATUS_INACTIVITY_DETECTED);
        } else {
            status = send_nak_for_missing_ranges(entity);
            if (status == CCSDS_CFDP_STATUS_OK) {
                entity->receiver.retry_count++;
                arm_retry(&entity->receiver, now_ms);
            } else {
                close_discard_receiver(entity);
                release_receiver_terminal(entity, status);
            }
        }
    }

    if (entity->receiver.active &&
        entity->receiver.transmission_mode ==
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED &&
        entity->receiver.waiting_for_finished_ack &&
        retry_due(&entity->receiver, now_ms)) {
        if (entity->receiver.retry_count >= CCSDS_CFDP_MAX_NAK_ROUNDS) {
            release_receiver_terminal(
                entity, CCSDS_CFDP_STATUS_INACTIVITY_DETECTED);
        } else {
            status = send_finished_for_receiver_status(
                entity, entity->receiver.finished_status);
            if (status == CCSDS_CFDP_STATUS_OK) {
                entity->receiver.retry_count++;
                arm_retry(&entity->receiver, now_ms);
            } else {
                release_receiver_terminal(entity, status);
            }
        }
    }

    if (entity->sender.active &&
        entity->sender.transmission_mode ==
            CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED &&
        !entity->sender.finished_received && retry_due(&entity->sender,
                                                       now_ms)) {
        if (entity->sender.retry_count >= CCSDS_CFDP_MAX_NAK_ROUNDS) {
            (void)sender_fail(entity, CCSDS_CFDP_STATUS_INACTIVITY_DETECTED);
        } else {
            status = send_eof(entity, entity->sender.eof_checksum,
                              entity->sender.file_size);
            if (status == CCSDS_CFDP_STATUS_OK) {
                entity->sender.retry_count++;
                arm_retry(&entity->sender, now_ms);
            } else {
                (void)sender_fail(entity, status);
            }
        }
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

    close_sender_handle(entity);
    memset(&entity->sender, 0, sizeof(entity->sender));
}

void ccsds_cfdp_entity_release_receiver_transaction(ccsds_cfdp_entity_t *entity)
{
    __ASSERT(entity != NULL, "CFDP entity is NULL");

    memset(&entity->receiver, 0, sizeof(entity->receiver));
}
