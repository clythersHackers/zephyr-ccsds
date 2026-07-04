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

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CFDP_PDU_H */
