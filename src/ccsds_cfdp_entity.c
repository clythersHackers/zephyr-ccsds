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

out_release:
    if (handle_open && filestore->close(filestore->user, handle) != 0 &&
        status == CCSDS_CFDP_STATUS_OK) {
        status = CCSDS_CFDP_STATUS_FILESTORE_REJECTION;
    }
    ccsds_cfdp_entity_release_sender_transaction(entity);
    return status;
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
