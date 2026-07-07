#include <zephyr/ztest.h>

#include "ccsds/ccsds_cfdp_types.h"

ZTEST(ccsds_cfdp_types, test_config_backed_limits)
{
    zassert_equal(CCSDS_CFDP_VERSION_1, 1u);
    zassert_equal(CCSDS_CFDP_MAX_ENTITY_ID_LEN,
                  CONFIG_AKIRA_CCSDS_CFDP_MAX_ENTITY_ID_LEN);
    zassert_equal(CCSDS_CFDP_MAX_TRANS_SEQ_LEN,
                  CONFIG_AKIRA_CCSDS_CFDP_MAX_TRANS_SEQ_LEN);
    zassert_equal(CCSDS_CFDP_MAX_FILENAME_LEN,
                  CONFIG_AKIRA_CCSDS_CFDP_MAX_FILENAME_LEN);
    zassert_equal(CCSDS_CFDP_MAX_PDU_SIZE,
                  CONFIG_AKIRA_CCSDS_CFDP_MAX_PDU_SIZE);
    zassert_equal(CCSDS_CFDP_MAX_SEGMENT_SIZE,
                  CONFIG_AKIRA_CCSDS_CFDP_MAX_SEGMENT_SIZE);
    zassert_equal(CCSDS_CFDP_MAX_NAK_RANGES,
                  CONFIG_AKIRA_CCSDS_CFDP_MAX_NAK_RANGES);
    zassert_equal(CCSDS_CFDP_MAX_NAK_ROUNDS,
                  CONFIG_AKIRA_CCSDS_CFDP_MAX_NAK_ROUNDS);
    zassert_equal(CCSDS_CFDP_MAX_ACTIVE_TX, 1u);
    zassert_equal(CCSDS_CFDP_MAX_ACTIVE_RX, 1u);
}

ZTEST(ccsds_cfdp_types, test_fixed_header_enums_match_standard_values)
{
    zassert_equal(CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE, 0);
    zassert_equal(CCSDS_CFDP_PDU_TYPE_FILE_DATA, 1);
    zassert_equal(CCSDS_CFDP_DIRECTION_TOWARD_RECEIVER, 0);
    zassert_equal(CCSDS_CFDP_DIRECTION_TOWARD_SENDER, 1);
    zassert_equal(CCSDS_CFDP_TRANSMISSION_MODE_ACKNOWLEDGED, 0);
    zassert_equal(CCSDS_CFDP_TRANSMISSION_MODE_UNACKNOWLEDGED, 1);
    zassert_equal(CCSDS_CFDP_CRC_NOT_PRESENT, 0);
    zassert_equal(CCSDS_CFDP_CRC_PRESENT, 1);
    zassert_equal(CCSDS_CFDP_FILE_SIZE_SMALL, 0);
    zassert_equal(CCSDS_CFDP_FILE_SIZE_LARGE, 1);
}

ZTEST(ccsds_cfdp_types, test_directive_and_condition_codes)
{
    zassert_equal(CCSDS_CFDP_DIRECTIVE_EOF, 0x04);
    zassert_equal(CCSDS_CFDP_DIRECTIVE_FINISHED, 0x05);
    zassert_equal(CCSDS_CFDP_DIRECTIVE_ACK, 0x06);
    zassert_equal(CCSDS_CFDP_DIRECTIVE_METADATA, 0x07);
    zassert_equal(CCSDS_CFDP_DIRECTIVE_NAK, 0x08);

    zassert_equal(CCSDS_CFDP_CONDITION_NO_ERROR, 0x0);
    zassert_equal(CCSDS_CFDP_CONDITION_INVALID_TRANSMISSION_MODE, 0x3);
    zassert_equal(CCSDS_CFDP_CONDITION_FILESTORE_REJECTION, 0x4);
    zassert_equal(CCSDS_CFDP_CONDITION_FILE_CHECKSUM_FAILURE, 0x5);
    zassert_equal(CCSDS_CFDP_CONDITION_FILE_SIZE_ERROR, 0x6);
    zassert_equal(CCSDS_CFDP_CONDITION_NAK_LIMIT_REACHED, 0x7);
    zassert_equal(CCSDS_CFDP_CONDITION_INACTIVITY_DETECTED, 0x8);
    zassert_equal(CCSDS_CFDP_CONDITION_UNSUPPORTED_CHECKSUM_TYPE, 0xB);
    zassert_equal(CCSDS_CFDP_CONDITION_CANCEL_REQUEST_RECEIVED, 0xF);
}

ZTEST(ccsds_cfdp_types, test_finished_and_checksum_enums)
{
    zassert_equal(CCSDS_CFDP_DELIVERY_CODE_DATA_COMPLETE, 0);
    zassert_equal(CCSDS_CFDP_DELIVERY_CODE_DATA_INCOMPLETE, 1);
    zassert_equal(CCSDS_CFDP_FILE_STATUS_DISCARDED_DELIBERATELY, 0);
    zassert_equal(CCSDS_CFDP_FILE_STATUS_DISCARDED_FILESTORE_REJECTION, 1);
    zassert_equal(CCSDS_CFDP_FILE_STATUS_RETAINED, 2);
    zassert_equal(CCSDS_CFDP_FILE_STATUS_UNREPORTED, 3);
    zassert_equal(CCSDS_CFDP_CHECKSUM_TYPE_MODULAR, 0);
    zassert_equal(CCSDS_CFDP_CHECKSUM_TYPE_CRC32C, 2);
    zassert_equal(CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS, 3);
    zassert_equal(CCSDS_CFDP_CHECKSUM_TYPE_NULL, 15);
}

ZTEST(ccsds_cfdp_types, test_status_codes_are_distinct)
{
    zassert_equal(CCSDS_CFDP_STATUS_OK, 0);
    zassert_not_equal(CCSDS_CFDP_STATUS_MALFORMED_PDU,
                      CCSDS_CFDP_STATUS_UNSUPPORTED);
    zassert_not_equal(CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM,
                      CCSDS_CFDP_STATUS_CHECKSUM_FAILURE);
}

ZTEST_SUITE(ccsds_cfdp_types, NULL, NULL, NULL, NULL, NULL);
