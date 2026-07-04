#include <zephyr/ztest.h>

#include <string.h>

#include "ccsds/ccsds_cfdp_pdu.h"

static ccsds_cfdp_pdu_header_t base_header(uint8_t entity_id_len,
                                           uint8_t trans_seq_len)
{
    return (ccsds_cfdp_pdu_header_t){
        .version = CCSDS_CFDP_VERSION_1,
        .pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE,
        .direction = CCSDS_CFDP_DIRECTION_TOWARD_RECEIVER,
        .transmission_mode = CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED,
        .crc_flag = CCSDS_CFDP_CRC_NOT_PRESENT,
        .file_size_mode = CCSDS_CFDP_FILE_SIZE_SMALL,
        .pdu_data_field_len = 0x0015u,
        .segmentation_control =
            CCSDS_CFDP_SEGMENTATION_RECORD_BOUNDARIES_NOT_PRESERVED,
        .segment_metadata_present = false,
        .entity_id_len = entity_id_len,
        .transaction_sequence_number_len = trans_seq_len,
        .source_entity_id = 0x12u,
        .transaction_sequence_number = 0x34u,
        .destination_entity_id = 0x56u,
    };
}

static void assert_headers_equal(const ccsds_cfdp_pdu_header_t *expected,
                                 const ccsds_cfdp_pdu_header_t *actual)
{
    zassert_equal(actual->version, expected->version);
    zassert_equal(actual->pdu_type, expected->pdu_type);
    zassert_equal(actual->direction, expected->direction);
    zassert_equal(actual->transmission_mode, expected->transmission_mode);
    zassert_equal(actual->crc_flag, expected->crc_flag);
    zassert_equal(actual->file_size_mode, expected->file_size_mode);
    zassert_equal(actual->pdu_data_field_len, expected->pdu_data_field_len);
    zassert_equal(actual->segmentation_control,
                  expected->segmentation_control);
    zassert_equal(actual->segment_metadata_present,
                  expected->segment_metadata_present);
    zassert_equal(actual->entity_id_len, expected->entity_id_len);
    zassert_equal(actual->transaction_sequence_number_len,
                  expected->transaction_sequence_number_len);
    zassert_equal(actual->source_entity_id, expected->source_entity_id);
    zassert_equal(actual->transaction_sequence_number,
                  expected->transaction_sequence_number);
    zassert_equal(actual->destination_entity_id,
                  expected->destination_entity_id);
}

ZTEST(ccsds_cfdp_pdu, test_header_encoded_len_for_supported_lengths)
{
    ccsds_cfdp_pdu_header_t header = base_header(1u, 1u);

    zassert_equal(ccsds_cfdp_header_encoded_len(&header), 7u);

    header.entity_id_len = 2u;
    header.transaction_sequence_number_len = 2u;
    zassert_equal(ccsds_cfdp_header_encoded_len(&header), 10u);

    header.entity_id_len = 4u;
    header.transaction_sequence_number_len = 4u;
    zassert_equal(ccsds_cfdp_header_encoded_len(&header), 16u);
}

ZTEST(ccsds_cfdp_pdu, test_encode_decode_one_octet_ids)
{
    ccsds_cfdp_pdu_header_t header = base_header(1u, 1u);
    ccsds_cfdp_pdu_header_t decoded;
    uint8_t buf[16];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x24u, 0x00u, 0x15u, 0x00u, 0x12u, 0x34u, 0x56u,
    };

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_header(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    assert_headers_equal(&header, &decoded);
}

ZTEST(ccsds_cfdp_pdu, test_encode_decode_two_octet_ids)
{
    ccsds_cfdp_pdu_header_t header = base_header(2u, 2u);
    ccsds_cfdp_pdu_header_t decoded;
    uint8_t buf[16];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x3cu, 0x12u, 0x34u, 0x99u, 0x12u, 0x34u, 0xabu,
        0xcdu, 0x56u, 0x78u,
    };

    header.pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DATA;
    header.direction = CCSDS_CFDP_DIRECTION_TOWARD_SENDER;
    header.transmission_mode = CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED;
    header.pdu_data_field_len = 0x1234u;
    header.segmentation_control =
        CCSDS_CFDP_SEGMENTATION_RECORD_BOUNDARIES_PRESERVED;
    header.segment_metadata_present = true;
    header.source_entity_id = 0x1234u;
    header.transaction_sequence_number = 0xabcdu;
    header.destination_entity_id = 0x5678u;

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_header(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    assert_headers_equal(&header, &decoded);
}

ZTEST(ccsds_cfdp_pdu, test_encode_decode_four_octet_ids)
{
    ccsds_cfdp_pdu_header_t header = base_header(4u, 4u);
    ccsds_cfdp_pdu_header_t decoded;
    uint8_t buf[20];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x20u, 0xffu, 0xffu, 0x33u, 0x01u, 0x02u, 0x03u, 0x04u,
        0xa1u, 0xa2u, 0xa3u, 0xa4u, 0x10u, 0x20u, 0x30u, 0x40u,
    };

    header.transmission_mode = CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED;
    header.pdu_data_field_len = 0xffffu;
    header.source_entity_id = 0x01020304u;
    header.transaction_sequence_number = 0xa1a2a3a4u;
    header.destination_entity_id = 0x10203040u;

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_header(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    assert_headers_equal(&header, &decoded);
}

ZTEST(ccsds_cfdp_pdu, test_decode_rejects_truncated_fixed_header)
{
    ccsds_cfdp_pdu_header_t decoded;
    size_t consumed;
    const uint8_t buf[] = { 0x20u, 0x00u, 0x00u };

    zassert_equal(ccsds_cfdp_decode_header(buf, sizeof(buf), &decoded,
                                           &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_decode_rejects_truncated_variable_fields)
{
    ccsds_cfdp_pdu_header_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x20u, 0x00u, 0x00u, 0x33u, 0x01u, 0x02u, 0x03u,
    };

    zassert_equal(ccsds_cfdp_decode_header(buf, sizeof(buf), &decoded,
                                           &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_decode_rejects_unsupported_version)
{
    ccsds_cfdp_pdu_header_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x40u, 0x00u, 0x00u, 0x00u, 0x01u, 0x02u, 0x03u,
    };

    zassert_equal(ccsds_cfdp_decode_header(buf, sizeof(buf), &decoded,
                                           &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_decode_rejects_large_file_mode)
{
    ccsds_cfdp_pdu_header_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x21u, 0x00u, 0x00u, 0x00u, 0x01u, 0x02u, 0x03u,
    };

    zassert_equal(ccsds_cfdp_decode_header(buf, sizeof(buf), &decoded,
                                           &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_decode_accepts_crc_present_without_validation)
{
    ccsds_cfdp_pdu_header_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x22u, 0x00u, 0x00u, 0x00u, 0x01u, 0x02u, 0x03u,
    };

    zassert_equal(ccsds_cfdp_decode_header(buf, sizeof(buf), &decoded,
                                           &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(decoded.crc_flag, CCSDS_CFDP_CRC_PRESENT);
    zassert_equal(consumed, sizeof(buf));
}

ZTEST(ccsds_cfdp_pdu, test_decode_rejects_lengths_above_configured_limits)
{
    ccsds_cfdp_pdu_header_t decoded;
    size_t consumed;
    uint8_t buf[] = {
        0x20u, 0x00u, 0x00u, 0x70u, 0x01u, 0x02u, 0x03u, 0x04u,
        0x05u, 0x06u, 0x07u, 0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu,
        0x0du, 0x0eu, 0x0fu, 0x10u, 0x11u,
    };

    zassert_equal(ccsds_cfdp_decode_header(buf, sizeof(buf), &decoded,
                                           &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_encode_rejects_large_file_mode)
{
    ccsds_cfdp_pdu_header_t header = base_header(1u, 1u);
    uint8_t buf[16];
    size_t len;

    header.file_size_mode = CCSDS_CFDP_FILE_SIZE_LARGE;

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_encode_preserves_crc_present_flag)
{
    ccsds_cfdp_pdu_header_t header = base_header(1u, 1u);
    uint8_t buf[16];
    size_t len;
    const uint8_t expected[] = {
        0x26u, 0x00u, 0x15u, 0x00u, 0x12u, 0x34u, 0x56u,
    };

    header.crc_flag = CCSDS_CFDP_CRC_PRESENT;

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));
}

ZTEST(ccsds_cfdp_pdu, test_encode_rejects_value_too_large_for_length)
{
    ccsds_cfdp_pdu_header_t header = base_header(1u, 1u);
    uint8_t buf[16];
    size_t len;

    header.source_entity_id = 0x100u;

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
}

ZTEST(ccsds_cfdp_pdu, test_encode_rejects_short_output_buffer)
{
    ccsds_cfdp_pdu_header_t header = base_header(1u, 1u);
    uint8_t buf[6];
    size_t len;

    zassert_equal(ccsds_cfdp_encode_header(&header, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL);
}

ZTEST(ccsds_cfdp_pdu, test_lv_zero_length_read_write)
{
    ccsds_cfdp_lv_t lv;
    uint8_t buf[1];
    size_t len;
    size_t consumed;

    zassert_equal(ccsds_cfdp_lv_write(NULL, 0u, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, 1u);
    zassert_equal(buf[0], 0u);

    zassert_equal(ccsds_cfdp_lv_read(buf, len, &lv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, 1u);
    zassert_equal(lv.len, 0u);
    zassert_is_null(lv.value);
}

ZTEST(ccsds_cfdp_pdu, test_lv_normal_read_write)
{
    const uint8_t value[] = { 0xaau, 0xbbu, 0xccu };
    ccsds_cfdp_lv_t lv;
    uint8_t buf[4];
    size_t len;
    size_t consumed;

    zassert_equal(ccsds_cfdp_lv_write(value, sizeof(value), buf, sizeof(buf),
                                      &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, 4u);
    zassert_equal(buf[0], sizeof(value));
    zassert_mem_equal(&buf[1], value, sizeof(value));

    zassert_equal(ccsds_cfdp_lv_read(buf, len, &lv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(lv.len, sizeof(value));
    zassert_true(lv.value == &buf[1]);
    zassert_mem_equal(lv.value, value, sizeof(value));
}

ZTEST(ccsds_cfdp_pdu, test_lv_max_one_octet_length_read_write)
{
    uint8_t value[255];
    uint8_t buf[256];
    ccsds_cfdp_lv_t lv;
    size_t len;
    size_t consumed;

    for (size_t i = 0u; i < sizeof(value); i++) {
        value[i] = (uint8_t)i;
    }

    zassert_equal(ccsds_cfdp_lv_write(value, sizeof(value), buf, sizeof(buf),
                                      &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(buf));
    zassert_equal(buf[0], 255u);
    zassert_mem_equal(&buf[1], value, sizeof(value));

    zassert_equal(ccsds_cfdp_lv_read(buf, len, &lv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, sizeof(buf));
    zassert_equal(lv.len, 255u);
    zassert_true(lv.value == &buf[1]);
    zassert_mem_equal(lv.value, value, sizeof(value));
}

ZTEST(ccsds_cfdp_pdu, test_lv_rejects_truncated_length_and_value)
{
    ccsds_cfdp_lv_t lv;
    size_t consumed;
    const uint8_t empty = 0u;
    const uint8_t truncated_value[] = { 3u, 0xaau, 0xbbu };

    zassert_equal(ccsds_cfdp_lv_read(&empty, 0u, &lv, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
    zassert_equal(ccsds_cfdp_lv_read(truncated_value,
                                     sizeof(truncated_value), &lv, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_lv_write_rejects_short_output_buffer)
{
    const uint8_t value[] = { 0xaau };
    uint8_t buf[1];
    size_t len;

    zassert_equal(ccsds_cfdp_lv_write(value, sizeof(value), buf, sizeof(buf),
                                      &len),
                  CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL);
}

ZTEST(ccsds_cfdp_pdu, test_tlv_zero_length_read_write)
{
    ccsds_cfdp_tlv_t tlv;
    uint8_t buf[2];
    size_t len;
    size_t consumed;

    zassert_equal(ccsds_cfdp_tlv_write(0x42u, NULL, 0u, buf, sizeof(buf),
                                       &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, 2u);
    zassert_equal(buf[0], 0x42u);
    zassert_equal(buf[1], 0u);

    zassert_equal(ccsds_cfdp_tlv_read(buf, len, &tlv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, 2u);
    zassert_equal(tlv.type, 0x42u);
    zassert_equal(tlv.len, 0u);
    zassert_is_null(tlv.value);
}

ZTEST(ccsds_cfdp_pdu, test_tlv_normal_read_write)
{
    const uint8_t value[] = { 0x11u, 0x22u, 0x33u, 0x44u };
    ccsds_cfdp_tlv_t tlv;
    uint8_t buf[6];
    size_t len;
    size_t consumed;

    zassert_equal(ccsds_cfdp_tlv_write(0x99u, value, sizeof(value), buf,
                                       sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, 6u);
    zassert_equal(buf[0], 0x99u);
    zassert_equal(buf[1], sizeof(value));
    zassert_mem_equal(&buf[2], value, sizeof(value));

    zassert_equal(ccsds_cfdp_tlv_read(buf, len, &tlv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(tlv.type, 0x99u);
    zassert_equal(tlv.len, sizeof(value));
    zassert_true(tlv.value == &buf[2]);
    zassert_mem_equal(tlv.value, value, sizeof(value));
}

ZTEST(ccsds_cfdp_pdu, test_tlv_max_one_octet_length_read_write)
{
    uint8_t value[255];
    uint8_t buf[257];
    ccsds_cfdp_tlv_t tlv;
    size_t len;
    size_t consumed;

    for (size_t i = 0u; i < sizeof(value); i++) {
        value[i] = (uint8_t)(255u - i);
    }

    zassert_equal(ccsds_cfdp_tlv_write(0x7eu, value, sizeof(value), buf,
                                       sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(buf));
    zassert_equal(buf[0], 0x7eu);
    zassert_equal(buf[1], 255u);
    zassert_mem_equal(&buf[2], value, sizeof(value));

    zassert_equal(ccsds_cfdp_tlv_read(buf, len, &tlv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, sizeof(buf));
    zassert_equal(tlv.type, 0x7eu);
    zassert_equal(tlv.len, 255u);
    zassert_true(tlv.value == &buf[2]);
    zassert_mem_equal(tlv.value, value, sizeof(value));
}

ZTEST(ccsds_cfdp_pdu, test_tlv_rejects_truncated_type_length_and_value)
{
    ccsds_cfdp_tlv_t tlv;
    size_t consumed;
    const uint8_t empty = 0u;
    const uint8_t missing_length[] = { 0x01u };
    const uint8_t truncated_value[] = { 0x01u, 3u, 0xaau, 0xbbu };

    zassert_equal(ccsds_cfdp_tlv_read(&empty, 0u, &tlv, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
    zassert_equal(ccsds_cfdp_tlv_read(missing_length,
                                      sizeof(missing_length), &tlv, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
    zassert_equal(ccsds_cfdp_tlv_read(truncated_value,
                                      sizeof(truncated_value), &tlv,
                                      &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_tlv_write_rejects_short_output_buffer)
{
    const uint8_t value[] = { 0xaau };
    uint8_t buf[2];
    size_t len;

    zassert_equal(ccsds_cfdp_tlv_write(0x01u, value, sizeof(value), buf,
                                       sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL);
}

ZTEST(ccsds_cfdp_pdu, test_tlv_walks_multiple_entries_with_consumed_lengths)
{
    const uint8_t buf[] = {
        0x01u, 2u, 0xaau, 0xbbu,
        0x02u, 0u,
        0x03u, 1u, 0xccu,
    };
    ccsds_cfdp_tlv_t tlv;
    size_t offset = 0u;
    size_t consumed;

    zassert_equal(ccsds_cfdp_tlv_read(&buf[offset], sizeof(buf) - offset,
                                      &tlv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(tlv.type, 0x01u);
    zassert_equal(tlv.len, 2u);
    zassert_true(tlv.value == &buf[2]);
    zassert_equal(consumed, 4u);
    offset += consumed;

    zassert_equal(ccsds_cfdp_tlv_read(&buf[offset], sizeof(buf) - offset,
                                      &tlv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(tlv.type, 0x02u);
    zassert_equal(tlv.len, 0u);
    zassert_is_null(tlv.value);
    zassert_equal(consumed, 2u);
    offset += consumed;

    zassert_equal(ccsds_cfdp_tlv_read(&buf[offset], sizeof(buf) - offset,
                                      &tlv, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(tlv.type, 0x03u);
    zassert_equal(tlv.len, 1u);
    zassert_true(tlv.value == &buf[8]);
    zassert_equal(tlv.value[0], 0xccu);
    zassert_equal(consumed, 3u);
    offset += consumed;

    zassert_equal(offset, sizeof(buf));
}

ZTEST(ccsds_cfdp_pdu, test_metadata_encode_decode_round_trip)
{
    const uint8_t source[] = "src";
    const uint8_t destination[] = "dst";
    ccsds_cfdp_metadata_pdu_t metadata = {
        .header = base_header(1u, 1u),
        .closure_requested = true,
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_NULL,
        .file_size = 0x00010203u,
        .source_filename = {
            .value = source,
            .len = sizeof(source) - 1u,
        },
        .destination_filename = {
            .value = destination,
            .len = sizeof(destination) - 1u,
        },
    };
    ccsds_cfdp_metadata_pdu_t decoded;
    uint8_t buf[32];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x24u, 0x00u, 0x0eu, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x4fu, 0x00u, 0x01u, 0x02u, 0x03u,
        0x03u, 's', 'r', 'c',
        0x03u, 'd', 's', 't',
    };

    metadata.header.pdu_data_field_len = 0u;

    zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_metadata(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(decoded.header.pdu_data_field_len, 0x000eu);
    zassert_equal(decoded.closure_requested, true);
    zassert_equal(decoded.checksum_type, CCSDS_CFDP_CHECKSUM_TYPE_NULL);
    zassert_equal(decoded.file_size, 0x00010203u);
    zassert_equal(decoded.source_filename.len, sizeof(source) - 1u);
    zassert_true(decoded.source_filename.value == &buf[14]);
    zassert_mem_equal(decoded.source_filename.value, source,
                      sizeof(source) - 1u);
    zassert_equal(decoded.destination_filename.len, sizeof(destination) - 1u);
    zassert_true(decoded.destination_filename.value == &buf[18]);
    zassert_mem_equal(decoded.destination_filename.value, destination,
                      sizeof(destination) - 1u);
}

ZTEST(ccsds_cfdp_pdu, test_metadata_encode_supports_standard_checksum_types)
{
    const uint8_t source[] = "a";
    const uint8_t destination[] = "b";
    const enum ccsds_cfdp_checksum_type supported[] = {
        CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        CCSDS_CFDP_CHECKSUM_TYPE_CRC32C,
        CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS,
        CCSDS_CFDP_CHECKSUM_TYPE_NULL,
    };
    ccsds_cfdp_metadata_pdu_t metadata = {
        .header = base_header(1u, 1u),
        .closure_requested = true,
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        .file_size = 1u,
        .source_filename = {
            .value = source,
            .len = sizeof(source) - 1u,
        },
        .destination_filename = {
            .value = destination,
            .len = sizeof(destination) - 1u,
        },
    };
    uint8_t buf[24];
    size_t len;

    metadata.header.transmission_mode =
        CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED;

    for (size_t i = 0u; i < ARRAY_SIZE(supported); i++) {
        metadata.checksum_type = supported[i];

        zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, sizeof(buf),
                                                 &len),
                      CCSDS_CFDP_STATUS_OK);
        zassert_equal(buf[8] & 0x0fu, supported[i]);
    }
}

ZTEST(ccsds_cfdp_pdu, test_metadata_rejects_unsupported_checksum_type)
{
    const uint8_t source[] = "src";
    const uint8_t destination[] = "dst";
    ccsds_cfdp_metadata_pdu_t metadata = {
        .header = base_header(1u, 1u),
        .closure_requested = true,
        .checksum_type = (enum ccsds_cfdp_checksum_type)1,
        .file_size = 1u,
        .source_filename = {
            .value = source,
            .len = sizeof(source) - 1u,
        },
        .destination_filename = {
            .value = destination,
            .len = sizeof(destination) - 1u,
        },
    };
    ccsds_cfdp_metadata_pdu_t decoded;
    uint8_t buf[32];
    size_t len;
    size_t consumed;
    const uint8_t unsupported_checksum[] = {
        0x24u, 0x00u, 0x0eu, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x41u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x03u, 's', 'r', 'c',
        0x03u, 'd', 's', 't',
    };

    zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM);
    zassert_equal(ccsds_cfdp_decode_metadata(unsupported_checksum,
                                             sizeof(unsupported_checksum),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM);
}

ZTEST(ccsds_cfdp_pdu, test_metadata_rejects_filenames_above_configured_limit)
{
    uint8_t long_name[CCSDS_CFDP_MAX_FILENAME_LEN + 1u];
    const uint8_t destination[] = "dst";
    ccsds_cfdp_metadata_pdu_t metadata = {
        .header = base_header(1u, 1u),
        .closure_requested = true,
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        .file_size = 1u,
        .source_filename = {
            .value = long_name,
            .len = sizeof(long_name),
        },
        .destination_filename = {
            .value = destination,
            .len = sizeof(destination) - 1u,
        },
    };
    ccsds_cfdp_metadata_pdu_t decoded;
    uint8_t buf[96] = {
        0x24u, 0x00u,
        (uint8_t)(CCSDS_CFDP_MAX_FILENAME_LEN + 12u),
        0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u,
        (uint8_t)(CCSDS_CFDP_MAX_FILENAME_LEN + 1u),
    };
    size_t len;
    size_t consumed;

    for (size_t i = 0u; i < sizeof(long_name); i++) {
        long_name[i] = (uint8_t)('a' + (i % 26u));
        buf[14u + i] = long_name[i];
    }
    buf[14u + sizeof(long_name)] = sizeof(destination) - 1u;
    memcpy(&buf[15u + sizeof(long_name)], destination,
           sizeof(destination) - 1u);

    zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_equal(ccsds_cfdp_decode_metadata(buf,
                                             15u + sizeof(long_name) +
                                                 sizeof(destination) - 1u,
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
}

ZTEST(ccsds_cfdp_pdu, test_metadata_rejects_empty_filenames)
{
    const uint8_t source[] = "src";
    const uint8_t destination[] = "dst";
    ccsds_cfdp_metadata_pdu_t metadata = {
        .header = base_header(1u, 1u),
        .closure_requested = true,
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        .file_size = 1u,
        .source_filename = {
            .value = NULL,
            .len = 0u,
        },
        .destination_filename = {
            .value = destination,
            .len = sizeof(destination) - 1u,
        },
    };
    ccsds_cfdp_metadata_pdu_t decoded;
    uint8_t buf[32];
    size_t len;
    size_t consumed;
    const uint8_t empty_source[] = {
        0x24u, 0x00u, 0x0bu, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x00u,
        0x03u, 'd', 's', 't',
    };
    const uint8_t empty_destination[] = {
        0x24u, 0x00u, 0x0bu, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x03u, 's', 'r', 'c',
        0x00u,
    };

    zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);

    metadata.source_filename.value = source;
    metadata.source_filename.len = sizeof(source) - 1u;
    metadata.destination_filename.value = NULL;
    metadata.destination_filename.len = 0u;
    zassert_equal(ccsds_cfdp_encode_metadata(&metadata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);

    zassert_equal(ccsds_cfdp_decode_metadata(empty_source,
                                             sizeof(empty_source), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_equal(ccsds_cfdp_decode_metadata(empty_destination,
                                             sizeof(empty_destination),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
}

ZTEST(ccsds_cfdp_pdu, test_metadata_rejects_truncated_filename_lv)
{
    ccsds_cfdp_metadata_pdu_t decoded;
    size_t consumed;
    const uint8_t truncated_destination[] = {
        0x24u, 0x00u, 0x0du, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x03u, 's', 'r', 'c',
        0x03u, 'd', 's',
    };

    zassert_equal(ccsds_cfdp_decode_metadata(truncated_destination,
                                             sizeof(truncated_destination),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_metadata_rejects_unexpected_options)
{
    ccsds_cfdp_metadata_pdu_t decoded;
    size_t consumed;
    const uint8_t with_option[] = {
        0x24u, 0x00u, 0x0du, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x01u, 's',
        0x01u, 'd',
        0x99u, 0x01u, 0xaau,
    };

    zassert_equal(ccsds_cfdp_decode_metadata(with_option, sizeof(with_option),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_metadata_rejects_truncated_option_tlv)
{
    ccsds_cfdp_metadata_pdu_t decoded;
    size_t consumed;
    const uint8_t truncated_option[] = {
        0x24u, 0x00u, 0x0bu, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x01u, 's',
        0x01u, 'd',
        0x99u,
    };

    zassert_equal(ccsds_cfdp_decode_metadata(truncated_option,
                                             sizeof(truncated_option),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_filedata_encode_decode_round_trip_offset_zero)
{
    const uint8_t payload[] = { 0xdeu, 0xadu, 0xbeu, 0xefu };
    ccsds_cfdp_filedata_pdu_t filedata = {
        .header = base_header(1u, 1u),
        .offset = 0u,
        .data = payload,
        .data_len = sizeof(payload),
    };
    ccsds_cfdp_filedata_pdu_t decoded;
    uint8_t buf[24];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x34u, 0x00u, 0x08u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0xdeu, 0xadu, 0xbeu, 0xefu,
    };

    filedata.header.pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DATA;
    filedata.header.pdu_data_field_len = 0u;

    zassert_equal(ccsds_cfdp_encode_filedata(&filedata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_filedata(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(decoded.header.pdu_type, CCSDS_CFDP_PDU_TYPE_FILE_DATA);
    zassert_equal(decoded.header.pdu_data_field_len,
                  4u + sizeof(payload));
    zassert_equal(decoded.offset, 0u);
    zassert_equal(decoded.data_len, sizeof(payload));
    zassert_true(decoded.data == &buf[11]);
    zassert_mem_equal(decoded.data, payload, sizeof(payload));
}

ZTEST(ccsds_cfdp_pdu, test_filedata_encode_decode_round_trip_nonzero_offset)
{
    const uint8_t payload[] = { 0x10u, 0x20u, 0x30u };
    ccsds_cfdp_filedata_pdu_t filedata = {
        .header = base_header(2u, 2u),
        .offset = 0x01020304u,
        .data = payload,
        .data_len = sizeof(payload),
    };
    ccsds_cfdp_filedata_pdu_t decoded;
    uint8_t buf[24];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x34u, 0x00u, 0x07u, 0x11u, 0x00u, 0x12u, 0x00u,
        0x34u, 0x00u, 0x56u, 0x01u, 0x02u, 0x03u, 0x04u,
        0x10u, 0x20u, 0x30u,
    };

    filedata.header.pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DATA;
    filedata.header.source_entity_id = 0x12u;
    filedata.header.transaction_sequence_number = 0x34u;
    filedata.header.destination_entity_id = 0x56u;

    zassert_equal(ccsds_cfdp_encode_filedata(&filedata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_filedata(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(decoded.offset, 0x01020304u);
    zassert_equal(decoded.data_len, sizeof(payload));
    zassert_true(decoded.data == &buf[14]);
    zassert_mem_equal(decoded.data, payload, sizeof(payload));
}

ZTEST(ccsds_cfdp_pdu, test_filedata_decode_payload_is_input_view)
{
    ccsds_cfdp_filedata_pdu_t decoded;
    size_t consumed;
    uint8_t buf[] = {
        0x34u, 0x00u, 0x06u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x00u, 0x00u, 0x00u, 0x2au,
        0xaau, 0xbbu,
    };

    zassert_equal(ccsds_cfdp_decode_filedata(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, sizeof(buf));
    zassert_true(decoded.data == &buf[11]);

    buf[11] = 0xccu;
    zassert_equal(decoded.data[0], 0xccu);
}

ZTEST(ccsds_cfdp_pdu, test_filedata_decode_rejects_segment_metadata)
{
    ccsds_cfdp_filedata_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x34u, 0x00u, 0x05u, 0x08u, 0x12u, 0x34u, 0x56u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0xaau,
    };

    zassert_equal(ccsds_cfdp_decode_filedata(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_filedata_rejects_large_file_mode)
{
    const uint8_t payload[] = { 0xaau };
    ccsds_cfdp_filedata_pdu_t filedata = {
        .header = base_header(1u, 1u),
        .offset = 0u,
        .data = payload,
        .data_len = sizeof(payload),
    };
    ccsds_cfdp_filedata_pdu_t decoded;
    uint8_t out[16];
    size_t len;
    size_t consumed;
    const uint8_t encoded[] = {
        0x35u, 0x00u, 0x05u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0xaau,
    };

    filedata.header.pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DATA;
    filedata.header.file_size_mode = CCSDS_CFDP_FILE_SIZE_LARGE;

    zassert_equal(ccsds_cfdp_encode_filedata(&filedata, out, sizeof(out),
                                             &len),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
    zassert_equal(ccsds_cfdp_decode_filedata(encoded, sizeof(encoded),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_filedata_decode_rejects_truncated_offset)
{
    ccsds_cfdp_filedata_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x34u, 0x00u, 0x03u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x00u, 0x00u, 0x00u,
    };

    zassert_equal(ccsds_cfdp_decode_filedata(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_filedata_decode_rejects_zero_length_file_data)
{
    ccsds_cfdp_filedata_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x34u, 0x00u, 0x04u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x00u, 0x00u, 0x00u, 0x00u,
    };

    zassert_equal(ccsds_cfdp_decode_filedata(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_filedata_encode_rejects_short_output_buffer)
{
    const uint8_t payload[] = { 0xaau };
    ccsds_cfdp_filedata_pdu_t filedata = {
        .header = base_header(1u, 1u),
        .offset = 0u,
        .data = payload,
        .data_len = sizeof(payload),
    };
    uint8_t buf[11];
    size_t len;

    filedata.header.pdu_type = CCSDS_CFDP_PDU_TYPE_FILE_DATA;

    zassert_equal(ccsds_cfdp_encode_filedata(&filedata, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL);
}

ZTEST(ccsds_cfdp_pdu, test_eof_encode_decode_round_trip_no_error)
{
    ccsds_cfdp_eof_pdu_t eof = {
        .header = base_header(1u, 1u),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .file_checksum = 0x01020304u,
        .file_size = 0x05060708u,
    };
    ccsds_cfdp_eof_pdu_t decoded;
    uint8_t buf[24];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x24u, 0x00u, 0x0au, 0x00u, 0x12u, 0x34u, 0x56u,
        0x04u, 0x00u, 0x01u, 0x02u, 0x03u, 0x04u,
        0x05u, 0x06u, 0x07u, 0x08u,
    };

    eof.header.pdu_data_field_len = 0u;

    zassert_equal(ccsds_cfdp_encode_eof(&eof, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_eof(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(decoded.header.pdu_type,
                  CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE);
    zassert_equal(decoded.header.pdu_data_field_len, 10u);
    zassert_equal(decoded.condition_code, CCSDS_CFDP_CONDITION_NO_ERROR);
    zassert_equal(decoded.file_checksum, 0x01020304u);
    zassert_equal(decoded.file_size, 0x05060708u);
}

ZTEST(ccsds_cfdp_pdu, test_eof_encode_decode_round_trip_nonzero_condition)
{
    ccsds_cfdp_eof_pdu_t eof = {
        .header = base_header(2u, 2u),
        .condition_code = CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE,
        .file_checksum = 0xa1a2a3a4u,
        .file_size = 0x10203040u,
    };
    ccsds_cfdp_eof_pdu_t decoded;
    uint8_t buf[24];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x24u, 0x00u, 0x0au, 0x11u, 0x00u, 0x12u, 0x00u,
        0x34u, 0x00u, 0x56u, 0x04u, 0x50u, 0xa1u, 0xa2u,
        0xa3u, 0xa4u, 0x10u, 0x20u, 0x30u, 0x40u,
    };

    eof.header.source_entity_id = 0x12u;
    eof.header.transaction_sequence_number = 0x34u;
    eof.header.destination_entity_id = 0x56u;

    zassert_equal(ccsds_cfdp_encode_eof(&eof, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_eof(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(decoded.condition_code,
                  CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE);
    zassert_equal(decoded.file_checksum, 0xa1a2a3a4u);
    zassert_equal(decoded.file_size, 0x10203040u);
}

ZTEST(ccsds_cfdp_pdu, test_eof_decode_rejects_file_data_pdu_type)
{
    ccsds_cfdp_eof_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x34u, 0x00u, 0x0au, 0x00u, 0x12u, 0x34u, 0x56u,
        0x04u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
    };

    zassert_equal(ccsds_cfdp_decode_eof(buf, sizeof(buf), &decoded,
                                        &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_eof_decode_rejects_non_eof_directive)
{
    ccsds_cfdp_eof_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x24u, 0x00u, 0x0au, 0x00u, 0x12u, 0x34u, 0x56u,
        0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
    };

    zassert_equal(ccsds_cfdp_decode_eof(buf, sizeof(buf), &decoded,
                                        &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_eof_rejects_large_file_mode)
{
    ccsds_cfdp_eof_pdu_t eof = {
        .header = base_header(1u, 1u),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .file_checksum = 0u,
        .file_size = 0u,
    };
    ccsds_cfdp_eof_pdu_t decoded;
    uint8_t out[24];
    size_t len;
    size_t consumed;
    const uint8_t encoded[] = {
        0x25u, 0x00u, 0x0au, 0x00u, 0x12u, 0x34u, 0x56u,
        0x04u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
    };

    eof.header.file_size_mode = CCSDS_CFDP_FILE_SIZE_LARGE;

    zassert_equal(ccsds_cfdp_encode_eof(&eof, out, sizeof(out), &len),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
    zassert_equal(ccsds_cfdp_decode_eof(encoded, sizeof(encoded), &decoded,
                                        &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_eof_decode_rejects_segment_metadata)
{
    ccsds_cfdp_eof_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x24u, 0x00u, 0x0au, 0x08u, 0x12u, 0x34u, 0x56u,
        0x04u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
    };

    zassert_equal(ccsds_cfdp_decode_eof(buf, sizeof(buf), &decoded,
                                        &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_eof_decode_rejects_truncated_fields)
{
    ccsds_cfdp_eof_pdu_t decoded;
    size_t consumed;
    const uint8_t truncated_condition[] = {
        0x24u, 0x00u, 0x0au, 0x00u, 0x12u, 0x34u, 0x56u,
        0x04u,
    };
    const uint8_t truncated_checksum[] = {
        0x24u, 0x00u, 0x0au, 0x00u, 0x12u, 0x34u, 0x56u,
        0x04u, 0x00u, 0x01u, 0x02u, 0x03u,
    };
    const uint8_t truncated_file_size[] = {
        0x24u, 0x00u, 0x0au, 0x00u, 0x12u, 0x34u, 0x56u,
        0x04u, 0x00u, 0x01u, 0x02u, 0x03u, 0x04u,
        0x05u, 0x06u, 0x07u,
    };

    zassert_equal(ccsds_cfdp_decode_eof(truncated_condition,
                                        sizeof(truncated_condition),
                                        &decoded, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
    zassert_equal(ccsds_cfdp_decode_eof(truncated_checksum,
                                        sizeof(truncated_checksum),
                                        &decoded, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
    zassert_equal(ccsds_cfdp_decode_eof(truncated_file_size,
                                        sizeof(truncated_file_size),
                                        &decoded, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_eof_encode_rejects_short_output_buffer)
{
    ccsds_cfdp_eof_pdu_t eof = {
        .header = base_header(1u, 1u),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .file_checksum = 0u,
        .file_size = 0u,
    };
    uint8_t buf[16];
    size_t len;

    zassert_equal(ccsds_cfdp_encode_eof(&eof, buf, sizeof(buf), &len),
                  CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL);
}

ZTEST(ccsds_cfdp_pdu,
      test_finished_encode_decode_round_trip_success_complete_retained)
{
    ccsds_cfdp_finished_pdu_t finished = {
        .header = base_header(1u, 1u),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .delivery_code = CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE,
        .file_status = CCSDS_CFDP_FILE_STATUS_RETAINED,
    };
    ccsds_cfdp_finished_pdu_t decoded;
    uint8_t buf[16];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x24u, 0x00u, 0x02u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x05u, 0x02u,
    };

    finished.header.pdu_data_field_len = 0u;

    zassert_equal(ccsds_cfdp_encode_finished(&finished, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_finished(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(decoded.header.pdu_type,
                  CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE);
    zassert_equal(decoded.header.pdu_data_field_len, 2u);
    zassert_equal(decoded.condition_code, CCSDS_CFDP_CONDITION_NO_ERROR);
    zassert_equal(decoded.delivery_code,
                  CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE);
    zassert_equal(decoded.file_status, CCSDS_CFDP_FILE_STATUS_RETAINED);
}

ZTEST(ccsds_cfdp_pdu,
      test_finished_encode_decode_round_trip_nonzero_condition_incomplete)
{
    ccsds_cfdp_finished_pdu_t finished = {
        .header = base_header(2u, 2u),
        .condition_code = CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE,
        .delivery_code = CCSDS_CFDP_DELIVERY_CODE_DATA_INCOMPLETE,
        .file_status = CCSDS_CFDP_FILE_STATUS_UNREPORTED,
    };
    ccsds_cfdp_finished_pdu_t decoded;
    uint8_t buf[16];
    size_t len;
    size_t consumed;
    const uint8_t expected[] = {
        0x24u, 0x00u, 0x02u, 0x11u, 0x00u, 0x12u, 0x00u,
        0x34u, 0x00u, 0x56u, 0x05u, 0x57u,
    };

    finished.header.source_entity_id = 0x12u;
    finished.header.transaction_sequence_number = 0x34u;
    finished.header.destination_entity_id = 0x56u;

    zassert_equal(ccsds_cfdp_encode_finished(&finished, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(len, sizeof(expected));
    zassert_mem_equal(buf, expected, sizeof(expected));

    memset(&decoded, 0, sizeof(decoded));
    zassert_equal(ccsds_cfdp_decode_finished(buf, len, &decoded, &consumed),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(consumed, len);
    zassert_equal(decoded.condition_code,
                  CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE);
    zassert_equal(decoded.delivery_code,
                  CCSDS_CFDP_DELIVERY_CODE_DATA_INCOMPLETE);
    zassert_equal(decoded.file_status, CCSDS_CFDP_FILE_STATUS_UNREPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_finished_decode_rejects_file_data_pdu_type)
{
    ccsds_cfdp_finished_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x34u, 0x00u, 0x02u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x05u, 0x02u,
    };

    zassert_equal(ccsds_cfdp_decode_finished(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_finished_decode_rejects_non_finished_directive)
{
    ccsds_cfdp_finished_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x24u, 0x00u, 0x02u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x04u, 0x02u,
    };

    zassert_equal(ccsds_cfdp_decode_finished(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_finished_rejects_large_file_mode)
{
    ccsds_cfdp_finished_pdu_t finished = {
        .header = base_header(1u, 1u),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .delivery_code = CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE,
        .file_status = CCSDS_CFDP_FILE_STATUS_RETAINED,
    };
    ccsds_cfdp_finished_pdu_t decoded;
    uint8_t out[16];
    size_t len;
    size_t consumed;
    const uint8_t encoded[] = {
        0x25u, 0x00u, 0x02u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x05u, 0x02u,
    };

    finished.header.file_size_mode = CCSDS_CFDP_FILE_SIZE_LARGE;

    zassert_equal(ccsds_cfdp_encode_finished(&finished, out, sizeof(out),
                                             &len),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
    zassert_equal(ccsds_cfdp_decode_finished(encoded, sizeof(encoded),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_UNSUPPORTED);
}

ZTEST(ccsds_cfdp_pdu, test_finished_decode_rejects_segment_metadata)
{
    ccsds_cfdp_finished_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x24u, 0x00u, 0x02u, 0x08u, 0x12u, 0x34u, 0x56u,
        0x05u, 0x02u,
    };

    zassert_equal(ccsds_cfdp_decode_finished(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_finished_decode_rejects_truncated_fields)
{
    ccsds_cfdp_finished_pdu_t decoded;
    size_t consumed;
    const uint8_t truncated_directive[] = {
        0x24u, 0x00u, 0x02u, 0x00u, 0x12u, 0x34u, 0x56u,
    };
    const uint8_t truncated_status[] = {
        0x24u, 0x00u, 0x02u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x05u,
    };

    zassert_equal(ccsds_cfdp_decode_finished(truncated_directive,
                                             sizeof(truncated_directive),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
    zassert_equal(ccsds_cfdp_decode_finished(truncated_status,
                                             sizeof(truncated_status),
                                             &decoded, &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_finished_decode_rejects_unexpected_extra_data)
{
    ccsds_cfdp_finished_pdu_t decoded;
    size_t consumed;
    const uint8_t buf[] = {
        0x24u, 0x00u, 0x04u, 0x00u, 0x12u, 0x34u, 0x56u,
        0x05u, 0x02u, 0x01u, 0x00u,
    };

    zassert_equal(ccsds_cfdp_decode_finished(buf, sizeof(buf), &decoded,
                                             &consumed),
                  CCSDS_CFDP_STATUS_MALFORMED_PDU);
}

ZTEST(ccsds_cfdp_pdu, test_finished_encode_rejects_short_output_buffer)
{
    ccsds_cfdp_finished_pdu_t finished = {
        .header = base_header(1u, 1u),
        .condition_code = CCSDS_CFDP_CONDITION_NO_ERROR,
        .delivery_code = CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE,
        .file_status = CCSDS_CFDP_FILE_STATUS_RETAINED,
    };
    uint8_t buf[8];
    size_t len;

    zassert_equal(ccsds_cfdp_encode_finished(&finished, buf, sizeof(buf),
                                             &len),
                  CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL);
}

ZTEST_SUITE(ccsds_cfdp_pdu, NULL, NULL, NULL, NULL, NULL);
