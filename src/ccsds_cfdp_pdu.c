#include "ccsds_cfdp_pdu.h"

#include <string.h>

#include <zephyr/sys/__assert.h>
#include <zephyr/sys/byteorder.h>

#define CCSDS_CFDP_FIXED_HEADER_MIN_LEN 4u
#define CCSDS_CFDP_MAX_ENCODED_INT_LEN 8u
#define CCSDS_CFDP_METADATA_MIN_DATA_LEN 8u
#define CCSDS_CFDP_METADATA_CLOSURE_REQUESTED 0x40u
#define CCSDS_CFDP_METADATA_RESERVED_MASK 0xb0u
#define CCSDS_CFDP_METADATA_CHECKSUM_MASK 0x0fu

static bool encoded_int_len_is_valid(uint8_t len, uint8_t max_len)
{
    return len >= 1u && len <= max_len && len <= CCSDS_CFDP_MAX_ENCODED_INT_LEN;
}

static bool header_lengths_are_valid(const ccsds_cfdp_pdu_header_t *header)
{
    return encoded_int_len_is_valid(header->entity_id_len,
                                    CCSDS_CFDP_MAX_ENTITY_ID_LEN) &&
           encoded_int_len_is_valid(header->transaction_sequence_number_len,
                                    CCSDS_CFDP_MAX_TRANS_SEQ_LEN);
}

static bool value_fits_len(uint64_t value, uint8_t len)
{
    if (len >= CCSDS_CFDP_MAX_ENCODED_INT_LEN) {
        return true;
    }

    return (value >> (len * 8u)) == 0u;
}

static void write_be_uint(uint8_t *buf, uint8_t len, uint64_t value)
{
    uint8_t encoded[CCSDS_CFDP_MAX_ENCODED_INT_LEN];

    sys_put_be64(value, encoded);
    memcpy(buf, &encoded[CCSDS_CFDP_MAX_ENCODED_INT_LEN - len], len);
}

static uint64_t read_be_uint(const uint8_t *buf, uint8_t len)
{
    uint8_t encoded[CCSDS_CFDP_MAX_ENCODED_INT_LEN] = { 0u };

    memcpy(&encoded[CCSDS_CFDP_MAX_ENCODED_INT_LEN - len], buf, len);

    return sys_get_be64(encoded);
}

static bool checksum_type_is_supported(enum ccsds_cfdp_checksum_type type)
{
    return type == CCSDS_CFDP_CHECKSUM_TYPE_MODULAR ||
           type == CCSDS_CFDP_CHECKSUM_TYPE_NULL;
}

static bool filename_len_is_valid(const ccsds_cfdp_lv_t *filename)
{
    return filename->len > 0u &&
           filename->len <= CCSDS_CFDP_MAX_FILENAME_LEN &&
           filename->value != NULL;
}

size_t ccsds_cfdp_header_encoded_len(const ccsds_cfdp_pdu_header_t *header)
{
    __ASSERT(header != NULL, "CFDP header is NULL");

    if (!header_lengths_are_valid(header)) {
        return 0u;
    }

    return CCSDS_CFDP_FIXED_HEADER_MIN_LEN +
           (2u * (size_t)header->entity_id_len) +
           header->transaction_sequence_number_len;
}

enum ccsds_cfdp_status
ccsds_cfdp_encode_header(const ccsds_cfdp_pdu_header_t *header, uint8_t *buf,
                         size_t cap, size_t *len)
{
    size_t needed;
    size_t offset;

    __ASSERT(header != NULL, "CFDP header is NULL");
    __ASSERT(buf != NULL, "CFDP header output buffer is NULL");
    __ASSERT(len != NULL, "CFDP header length output is NULL");

    if (header->version != CCSDS_CFDP_VERSION_1 ||
        header->pdu_type > CCSDS_CFDP_PDU_TYPE_FILE_DATA ||
        header->direction > CCSDS_CFDP_DIRECTION_TOWARD_SENDER ||
        header->transmission_mode >
            CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED ||
        header->crc_flag > CCSDS_CFDP_CRC_PRESENT ||
        header->segmentation_control >
            CCSDS_CFDP_SEGMENTATION_RECORD_BOUNDARIES_PRESERVED) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    if (header->file_size_mode != CCSDS_CFDP_FILE_SIZE_SMALL) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    if (!header_lengths_are_valid(header) ||
        !value_fits_len(header->source_entity_id, header->entity_id_len) ||
        !value_fits_len(header->transaction_sequence_number,
                        header->transaction_sequence_number_len) ||
        !value_fits_len(header->destination_entity_id, header->entity_id_len)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    needed = ccsds_cfdp_header_encoded_len(header);
    if (cap < needed) {
        return CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL;
    }

    buf[0] = (uint8_t)((header->version & 0x7u) << 5) |
             (uint8_t)((header->pdu_type & 0x1u) << 4) |
             (uint8_t)((header->direction & 0x1u) << 3) |
             (uint8_t)((header->transmission_mode & 0x1u) << 2) |
             (uint8_t)((header->crc_flag & 0x1u) << 1) |
             (uint8_t)(header->file_size_mode & 0x1u);
    sys_put_be16(header->pdu_data_field_len, &buf[1]);
    buf[3] = (uint8_t)((header->segmentation_control & 0x1u) << 7) |
             (uint8_t)(((header->entity_id_len - 1u) & 0x7u) << 4) |
             (header->segment_metadata_present ? 0x08u : 0u) |
             (uint8_t)((header->transaction_sequence_number_len - 1u) & 0x7u);

    offset = CCSDS_CFDP_FIXED_HEADER_MIN_LEN;
    write_be_uint(&buf[offset], header->entity_id_len,
                  header->source_entity_id);
    offset += header->entity_id_len;
    write_be_uint(&buf[offset], header->transaction_sequence_number_len,
                  header->transaction_sequence_number);
    offset += header->transaction_sequence_number_len;
    write_be_uint(&buf[offset], header->entity_id_len,
                  header->destination_entity_id);

    *len = needed;
    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_decode_header(const uint8_t *buf, size_t len,
                         ccsds_cfdp_pdu_header_t *header, size_t *consumed)
{
    uint8_t entity_id_len;
    uint8_t trans_seq_len;
    size_t needed;
    size_t offset;
    uint8_t version;
    enum ccsds_cfdp_file_size_mode file_size_mode;
    enum ccsds_cfdp_crc_flag crc_flag;

    __ASSERT(buf != NULL, "CFDP header input buffer is NULL");
    __ASSERT(header != NULL, "CFDP header output is NULL");
    __ASSERT(consumed != NULL, "CFDP consumed length output is NULL");

    if (len < CCSDS_CFDP_FIXED_HEADER_MIN_LEN) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    version = (uint8_t)((buf[0] >> 5) & 0x7u);
    if (version != CCSDS_CFDP_VERSION_1) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    file_size_mode = (enum ccsds_cfdp_file_size_mode)(buf[0] & 0x1u);
    if (file_size_mode != CCSDS_CFDP_FILE_SIZE_SMALL) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    crc_flag = (enum ccsds_cfdp_crc_flag)((buf[0] >> 1) & 0x1u);
    entity_id_len = (uint8_t)(((buf[3] >> 4) & 0x7u) + 1u);
    trans_seq_len = (uint8_t)((buf[3] & 0x7u) + 1u);
    if (!encoded_int_len_is_valid(entity_id_len,
                                  CCSDS_CFDP_MAX_ENTITY_ID_LEN) ||
        !encoded_int_len_is_valid(trans_seq_len,
                                  CCSDS_CFDP_MAX_TRANS_SEQ_LEN)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    needed = CCSDS_CFDP_FIXED_HEADER_MIN_LEN + (2u * (size_t)entity_id_len) +
             trans_seq_len;
    if (len < needed) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    header->version = version;
    header->pdu_type = (enum ccsds_cfdp_pdu_type)((buf[0] >> 4) & 0x1u);
    header->direction = (enum ccsds_cfdp_direction)((buf[0] >> 3) & 0x1u);
    header->transmission_mode =
        (enum ccsds_cfdp_transmission_mode)((buf[0] >> 2) & 0x1u);
    header->crc_flag = crc_flag;
    header->file_size_mode = file_size_mode;
    header->pdu_data_field_len = sys_get_be16(&buf[1]);
    header->segmentation_control =
        (enum ccsds_cfdp_segmentation_control)((buf[3] >> 7) & 0x1u);
    header->segment_metadata_present = (buf[3] & 0x08u) != 0u;
    header->entity_id_len = entity_id_len;
    header->transaction_sequence_number_len = trans_seq_len;

    offset = CCSDS_CFDP_FIXED_HEADER_MIN_LEN;
    header->source_entity_id = read_be_uint(&buf[offset], entity_id_len);
    offset += entity_id_len;
    header->transaction_sequence_number = read_be_uint(&buf[offset],
                                                       trans_seq_len);
    offset += trans_seq_len;
    header->destination_entity_id = read_be_uint(&buf[offset], entity_id_len);

    *consumed = needed;
    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status ccsds_cfdp_lv_read(const uint8_t *buf, size_t len,
                                          ccsds_cfdp_lv_t *lv,
                                          size_t *consumed)
{
    uint8_t value_len;

    __ASSERT(buf != NULL, "CFDP LV input buffer is NULL");
    __ASSERT(lv != NULL, "CFDP LV output is NULL");
    __ASSERT(consumed != NULL, "CFDP LV consumed length output is NULL");

    if (len < 1u) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    value_len = buf[0];
    if ((len - 1u) < value_len) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    lv->len = value_len;
    lv->value = (value_len == 0u) ? NULL : &buf[1];
    *consumed = 1u + value_len;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status ccsds_cfdp_lv_write(const uint8_t *value,
                                           uint8_t value_len, uint8_t *buf,
                                           size_t cap, size_t *written)
{
    size_t needed = 1u + (size_t)value_len;

    __ASSERT(value != NULL || value_len == 0u, "CFDP LV value is NULL");
    __ASSERT(buf != NULL, "CFDP LV output buffer is NULL");
    __ASSERT(written != NULL, "CFDP LV written length output is NULL");

    if (cap < needed) {
        return CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL;
    }

    buf[0] = value_len;
    for (uint8_t i = 0u; i < value_len; i++) {
        buf[1u + i] = value[i];
    }

    *written = needed;
    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_encode_metadata(const ccsds_cfdp_metadata_pdu_t *metadata,
                           uint8_t *buf, size_t cap, size_t *len)
{
    ccsds_cfdp_pdu_header_t header;
    size_t header_len;
    size_t pdu_data_len;
    size_t offset;
    size_t written;
    enum ccsds_cfdp_status status;

    __ASSERT(metadata != NULL, "CFDP Metadata PDU is NULL");
    __ASSERT(buf != NULL, "CFDP Metadata output buffer is NULL");
    __ASSERT(len != NULL, "CFDP Metadata length output is NULL");

    if (metadata->header.pdu_type != CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE ||
        metadata->header.file_size_mode != CCSDS_CFDP_FILE_SIZE_SMALL ||
        metadata->header.segment_metadata_present) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    if (!checksum_type_is_supported(metadata->checksum_type)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM;
    }

    if (!filename_len_is_valid(&metadata->source_filename) ||
        !filename_len_is_valid(&metadata->destination_filename)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    pdu_data_len = CCSDS_CFDP_METADATA_MIN_DATA_LEN +
                   (size_t)metadata->source_filename.len +
                   (size_t)metadata->destination_filename.len;
    if (pdu_data_len > UINT16_MAX) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    header = metadata->header;
    header.pdu_data_field_len = (uint16_t)pdu_data_len;
    status = ccsds_cfdp_encode_header(&header, buf, cap, &header_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if ((cap - header_len) < pdu_data_len) {
        return CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL;
    }

    offset = header_len;
    buf[offset++] = CCSDS_CFDP_DIRECTIVE_METADATA;
    buf[offset++] =
        (metadata->closure_requested &&
                 header.transmission_mode !=
                     CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED ?
             CCSDS_CFDP_METADATA_CLOSURE_REQUESTED :
             0u) |
        (uint8_t)(metadata->checksum_type & CCSDS_CFDP_METADATA_CHECKSUM_MASK);
    write_be_uint(&buf[offset], 4u, metadata->file_size);
    offset += 4u;

    status = ccsds_cfdp_lv_write(metadata->source_filename.value,
                                 metadata->source_filename.len, &buf[offset],
                                 cap - offset, &written);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    offset += written;

    status = ccsds_cfdp_lv_write(metadata->destination_filename.value,
                                 metadata->destination_filename.len,
                                 &buf[offset], cap - offset, &written);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    offset += written;

    *len = offset;
    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_decode_metadata(const uint8_t *buf, size_t len,
                           ccsds_cfdp_metadata_pdu_t *metadata,
                           size_t *consumed)
{
    ccsds_cfdp_pdu_header_t header;
    size_t header_len;
    size_t pdu_end;
    size_t offset;
    size_t field_consumed;
    ccsds_cfdp_lv_t source_filename;
    ccsds_cfdp_lv_t destination_filename;
    enum ccsds_cfdp_checksum_type checksum_type;
    enum ccsds_cfdp_status status;
    uint8_t metadata_control;

    __ASSERT(buf != NULL, "CFDP Metadata input buffer is NULL");
    __ASSERT(metadata != NULL, "CFDP Metadata output is NULL");
    __ASSERT(consumed != NULL, "CFDP Metadata consumed length output is NULL");

    status = ccsds_cfdp_decode_header(buf, len, &header, &header_len);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if (header.pdu_type != CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE ||
        header.file_size_mode != CCSDS_CFDP_FILE_SIZE_SMALL ||
        header.segment_metadata_present) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    if (header.pdu_data_field_len < CCSDS_CFDP_METADATA_MIN_DATA_LEN ||
        (len - header_len) < header.pdu_data_field_len) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    pdu_end = header_len + header.pdu_data_field_len;
    offset = header_len;

    if (buf[offset++] != CCSDS_CFDP_DIRECTIVE_METADATA) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    metadata_control = buf[offset++];
    if ((metadata_control & CCSDS_CFDP_METADATA_RESERVED_MASK) != 0u) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    checksum_type = (enum ccsds_cfdp_checksum_type)(
        metadata_control & CCSDS_CFDP_METADATA_CHECKSUM_MASK);
    if (!checksum_type_is_supported(checksum_type)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM;
    }

    if ((pdu_end - offset) < 4u) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }
    metadata->file_size = (uint32_t)read_be_uint(&buf[offset], 4u);
    offset += 4u;

    status = ccsds_cfdp_lv_read(&buf[offset], pdu_end - offset,
                                &source_filename, &field_consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (!filename_len_is_valid(&source_filename)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }
    offset += field_consumed;

    status = ccsds_cfdp_lv_read(&buf[offset], pdu_end - offset,
                                &destination_filename, &field_consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }
    if (!filename_len_is_valid(&destination_filename)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }
    offset += field_consumed;

    if (offset < pdu_end) {
        ccsds_cfdp_tlv_t tlv;

        status = ccsds_cfdp_tlv_read(&buf[offset], pdu_end - offset, &tlv,
                                     &field_consumed);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }

        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    metadata->header = header;
    metadata->closure_requested =
        (metadata_control & CCSDS_CFDP_METADATA_CLOSURE_REQUESTED) != 0u;
    metadata->checksum_type = checksum_type;
    metadata->source_filename = source_filename;
    metadata->destination_filename = destination_filename;
    *consumed = pdu_end;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status ccsds_cfdp_tlv_read(const uint8_t *buf, size_t len,
                                           ccsds_cfdp_tlv_t *tlv,
                                           size_t *consumed)
{
    uint8_t value_len;

    __ASSERT(buf != NULL, "CFDP TLV input buffer is NULL");
    __ASSERT(tlv != NULL, "CFDP TLV output is NULL");
    __ASSERT(consumed != NULL, "CFDP TLV consumed length output is NULL");

    if (len < 1u) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    if (len < 2u) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    value_len = buf[1];
    if ((len - 2u) < value_len) {
        return CCSDS_CFDP_STATUS_MALFORMED_PDU;
    }

    tlv->type = buf[0];
    tlv->len = value_len;
    tlv->value = (value_len == 0u) ? NULL : &buf[2];
    *consumed = 2u + value_len;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status ccsds_cfdp_tlv_write(uint8_t type,
                                            const uint8_t *value,
                                            uint8_t value_len, uint8_t *buf,
                                            size_t cap, size_t *written)
{
    size_t needed = 2u + (size_t)value_len;

    __ASSERT(value != NULL || value_len == 0u, "CFDP TLV value is NULL");
    __ASSERT(buf != NULL, "CFDP TLV output buffer is NULL");
    __ASSERT(written != NULL, "CFDP TLV written length output is NULL");

    if (cap < needed) {
        return CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL;
    }

    buf[0] = type;
    buf[1] = value_len;
    for (uint8_t i = 0u; i < value_len; i++) {
        buf[2u + i] = value[i];
    }

    *written = needed;
    return CCSDS_CFDP_STATUS_OK;
}
