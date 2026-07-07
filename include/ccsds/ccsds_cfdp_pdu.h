/**
 * @file ccsds_cfdp_pdu.h
 * @brief CCSDS CFDP fixed PDU header codec for the AkiraOS subset.
 */

#ifndef AKIRA_CCSDS_CFDP_PDU_H
#define AKIRA_CCSDS_CFDP_PDU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ccsds_cfdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_cfdp_pdu_header {
    uint8_t version;
    enum ccsds_cfdp_pdu_type pdu_type;
    enum ccsds_cfdp_direction direction;
    enum ccsds_cfdp_transmission_mode transmission_mode;
    enum ccsds_cfdp_crc_flag crc_flag;
    enum ccsds_cfdp_file_size_mode file_size_mode;
    uint16_t pdu_data_field_len;
    enum ccsds_cfdp_segmentation_control segmentation_control;
    bool segment_metadata_present;
    uint8_t entity_id_len;
    uint8_t transaction_sequence_number_len;
    uint64_t source_entity_id;
    uint64_t transaction_sequence_number;
    uint64_t destination_entity_id;
};

typedef struct ccsds_cfdp_pdu_header ccsds_cfdp_pdu_header_t;

struct ccsds_cfdp_lv {
    const uint8_t *value;
    uint8_t len;
};

typedef struct ccsds_cfdp_lv ccsds_cfdp_lv_t;

struct ccsds_cfdp_tlv {
    uint8_t type;
    const uint8_t *value;
    uint8_t len;
};

typedef struct ccsds_cfdp_tlv ccsds_cfdp_tlv_t;

struct ccsds_cfdp_metadata_pdu {
    ccsds_cfdp_pdu_header_t header;
    bool closure_requested;
    enum ccsds_cfdp_checksum_type checksum_type;
    uint32_t file_size;
    ccsds_cfdp_lv_t source_filename;
    ccsds_cfdp_lv_t destination_filename;
};

typedef struct ccsds_cfdp_metadata_pdu ccsds_cfdp_metadata_pdu_t;

struct ccsds_cfdp_filedata_pdu {
    ccsds_cfdp_pdu_header_t header;
    uint32_t offset;
    const uint8_t *data;
    size_t data_len;
};

typedef struct ccsds_cfdp_filedata_pdu ccsds_cfdp_filedata_pdu_t;

struct ccsds_cfdp_eof_pdu {
    ccsds_cfdp_pdu_header_t header;
    enum ccsds_cfdp_condition_code condition_code;
    uint32_t file_checksum;
    uint32_t file_size;
};

typedef struct ccsds_cfdp_eof_pdu ccsds_cfdp_eof_pdu_t;

struct ccsds_cfdp_finished_pdu {
    ccsds_cfdp_pdu_header_t header;
    enum ccsds_cfdp_condition_code condition_code;
    enum ccsds_cfdp_delivery_code delivery_code;
    enum ccsds_cfdp_file_status file_status;
};

typedef struct ccsds_cfdp_finished_pdu ccsds_cfdp_finished_pdu_t;

struct ccsds_cfdp_ack_pdu {
    ccsds_cfdp_pdu_header_t header;
    enum ccsds_cfdp_directive_code acknowledged_directive;
    enum ccsds_cfdp_ack_directive_subtype directive_subtype;
    enum ccsds_cfdp_condition_code condition_code;
    enum ccsds_cfdp_transaction_status transaction_status;
};

typedef struct ccsds_cfdp_ack_pdu ccsds_cfdp_ack_pdu_t;

struct ccsds_cfdp_nak_range {
    uint32_t start;
    uint32_t end;
};

typedef struct ccsds_cfdp_nak_range ccsds_cfdp_nak_range_t;

struct ccsds_cfdp_nak_pdu {
    ccsds_cfdp_pdu_header_t header;
    uint32_t scope_start;
    uint32_t scope_end;
    ccsds_cfdp_nak_range_t ranges[CCSDS_CFDP_MAX_NAK_RANGES];
    size_t range_count;
};

typedef struct ccsds_cfdp_nak_pdu ccsds_cfdp_nak_pdu_t;

/**
 * @brief Return the encoded fixed-header length for the selected ID lengths.
 *
 * @param header Header fields containing entity and transaction sequence
 *        number lengths in octets.
 *
 * @return Encoded fixed-header length in octets, or 0 for invalid lengths.
 */
size_t ccsds_cfdp_header_encoded_len(const ccsds_cfdp_pdu_header_t *header);

/**
 * @brief Encode a CFDP fixed PDU header.
 *
 * @param header Header fields to encode.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param len Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_encode_header(const ccsds_cfdp_pdu_header_t *header, uint8_t *buf,
                         size_t cap, size_t *len);

/**
 * @brief Decode a CFDP fixed PDU header.
 *
 * @param buf Encoded CFDP fixed header bytes.
 * @param len Input length in octets.
 * @param header Output decoded header.
 * @param consumed Number of fixed-header octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_decode_header(const uint8_t *buf, size_t len,
                         ccsds_cfdp_pdu_header_t *header, size_t *consumed);

/**
 * @brief Decode a bounded CFDP length-value field as a value view.
 *
 * @param buf Encoded LV bytes.
 * @param len Input length in octets.
 * @param lv Output decoded value view. The value pointer aliases @p buf.
 * @param consumed Number of LV octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_lv_read(const uint8_t *buf, size_t len,
                                          ccsds_cfdp_lv_t *lv,
                                          size_t *consumed);

/**
 * @brief Encode a bounded CFDP length-value field.
 *
 * @param value Value bytes to encode, or NULL when @p value_len is zero.
 * @param value_len Value length in octets.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param written Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_lv_write(const uint8_t *value,
                                           uint8_t value_len, uint8_t *buf,
                                           size_t cap, size_t *written);

/**
 * @brief Decode a bounded CFDP type-length-value field as a value view.
 *
 * @param buf Encoded TLV bytes.
 * @param len Input length in octets.
 * @param tlv Output decoded type and value view. The value pointer aliases
 *        @p buf.
 * @param consumed Number of TLV octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_tlv_read(const uint8_t *buf, size_t len,
                                           ccsds_cfdp_tlv_t *tlv,
                                           size_t *consumed);

/**
 * @brief Encode a bounded CFDP type-length-value field.
 *
 * @param type TLV type octet.
 * @param value Value bytes to encode, or NULL when @p value_len is zero.
 * @param value_len Value length in octets.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param written Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_tlv_write(uint8_t type,
                                            const uint8_t *value,
                                            uint8_t value_len, uint8_t *buf,
                                            size_t cap, size_t *written);

/**
 * @brief Encode a complete CFDP Metadata PDU.
 *
 * The fixed-header PDU data field length is derived from the metadata fields.
 *
 * @param metadata Metadata PDU fields to encode.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param len Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_encode_metadata(const ccsds_cfdp_metadata_pdu_t *metadata,
                           uint8_t *buf, size_t cap, size_t *len);

/**
 * @brief Decode a complete CFDP Metadata PDU.
 *
 * Filename values are returned as pointer+length views into @p buf.
 *
 * @param buf Encoded CFDP Metadata PDU bytes.
 * @param len Input length in octets.
 * @param metadata Output decoded metadata PDU.
 * @param consumed Number of PDU octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_decode_metadata(const uint8_t *buf, size_t len,
                           ccsds_cfdp_metadata_pdu_t *metadata,
                           size_t *consumed);

/**
 * @brief Encode a complete CFDP File Data PDU.
 *
 * The fixed-header PDU data field length is derived from the file data fields.
 * Only normal 32-bit offset mode without segment metadata is supported.
 *
 * @param filedata File Data PDU fields to encode.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param len Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_encode_filedata(const ccsds_cfdp_filedata_pdu_t *filedata,
                           uint8_t *buf, size_t cap, size_t *len);

/**
 * @brief Decode a complete CFDP File Data PDU.
 *
 * File data is returned as a pointer+length view into @p buf.
 *
 * @param buf Encoded CFDP File Data PDU bytes.
 * @param len Input length in octets.
 * @param filedata Output decoded File Data PDU.
 * @param consumed Number of PDU octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_decode_filedata(const uint8_t *buf, size_t len,
                           ccsds_cfdp_filedata_pdu_t *filedata,
                           size_t *consumed);

/**
 * @brief Encode a complete CFDP EOF PDU.
 *
 * The fixed-header PDU data field length is derived from the EOF fields.
 * Only normal 32-bit file size mode without segment metadata is supported.
 *
 * @param eof EOF PDU fields to encode.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param len Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_encode_eof(const ccsds_cfdp_eof_pdu_t *eof, uint8_t *buf,
                      size_t cap, size_t *len);

/**
 * @brief Decode a complete CFDP EOF PDU.
 *
 * @param buf Encoded CFDP EOF PDU bytes.
 * @param len Input length in octets.
 * @param eof Output decoded EOF PDU.
 * @param consumed Number of PDU octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_decode_eof(const uint8_t *buf, size_t len,
                      ccsds_cfdp_eof_pdu_t *eof, size_t *consumed);

/**
 * @brief Encode a complete CFDP Finished PDU.
 *
 * The fixed-header PDU data field length is derived from the Finished fields.
 * Only normal 32-bit file size mode without segment metadata is supported.
 * Filestore response TLVs are not supported.
 *
 * @param finished Finished PDU fields to encode.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param len Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_encode_finished(const ccsds_cfdp_finished_pdu_t *finished,
                           uint8_t *buf, size_t cap, size_t *len);

/**
 * @brief Decode a complete CFDP Finished PDU.
 *
 * Filestore response TLVs are not supported and are rejected as extra data.
 *
 * @param buf Encoded CFDP Finished PDU bytes.
 * @param len Input length in octets.
 * @param finished Output decoded Finished PDU.
 * @param consumed Number of PDU octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_decode_finished(const uint8_t *buf, size_t len,
                           ccsds_cfdp_finished_pdu_t *finished,
                           size_t *consumed);

/**
 * @brief Encode a complete CFDP ACK PDU for EOF or Finished.
 *
 * @param ack ACK PDU fields to encode.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param len Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_encode_ack(const ccsds_cfdp_ack_pdu_t *ack,
                                             uint8_t *buf, size_t cap,
                                             size_t *len);

/**
 * @brief Decode a complete CFDP ACK PDU for EOF or Finished.
 *
 * @param buf Encoded CFDP ACK PDU bytes.
 * @param len Input length in octets.
 * @param ack Output decoded ACK PDU.
 * @param consumed Number of PDU octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_decode_ack(const uint8_t *buf, size_t len,
                                             ccsds_cfdp_ack_pdu_t *ack,
                                             size_t *consumed);

/**
 * @brief Encode a complete CFDP NAK PDU with normal 32-bit offsets.
 *
 * @param nak NAK PDU fields to encode.
 * @param buf Output buffer.
 * @param cap Output buffer capacity in octets.
 * @param len Written encoded length in octets.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_encode_nak(const ccsds_cfdp_nak_pdu_t *nak,
                                             uint8_t *buf, size_t cap,
                                             size_t *len);

/**
 * @brief Decode a complete CFDP NAK PDU with normal 32-bit offsets.
 *
 * @param buf Encoded CFDP NAK PDU bytes.
 * @param len Input length in octets.
 * @param nak Output decoded NAK PDU.
 * @param consumed Number of PDU octets consumed.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_decode_nak(const uint8_t *buf, size_t len,
                                             ccsds_cfdp_nak_pdu_t *nak,
                                             size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CFDP_PDU_H */
