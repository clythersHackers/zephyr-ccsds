#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <ccsds/ccsds_space_packet.h>

ZTEST(ccsds_space_packet, test_known_packet_round_trip)
{
    static const uint8_t payload[] = { 0xde, 0xad, 0xbe };
    static const uint8_t expected[] = {
        0x18, 0x01, 0xc0, 0x2a, 0x00, 0x02, 0xde, 0xad, 0xbe,
    };
    const struct ccsds_space_packet input = {
        .version = 0u,
        .type = CCSDS_PACKET_TYPE_TC,
        .secondary_header = true,
        .apid = 1u,
        .sequence_flags = CCSDS_SEQUENCE_UNSEGMENTED,
        .sequence_count = 42u,
        .payload = payload,
        .payload_len = sizeof(payload),
    };
    struct ccsds_space_packet output;
    uint8_t encoded[sizeof(expected)];
    size_t encoded_len;

    zassert_ok(ccsds_space_packet_encode(&input, encoded, sizeof(encoded),
                                         &encoded_len));
    zassert_equal(encoded_len, sizeof(expected));
    zassert_mem_equal(encoded, expected, sizeof(expected));

    zassert_ok(ccsds_space_packet_decode(encoded, encoded_len, &output));
    zassert_equal(output.version, input.version);
    zassert_equal(output.type, input.type);
    zassert_equal(output.secondary_header, input.secondary_header);
    zassert_equal(output.apid, input.apid);
    zassert_equal(output.sequence_flags, input.sequence_flags);
    zassert_equal(output.sequence_count, input.sequence_count);
    zassert_equal(output.payload_len, input.payload_len);
    zassert_mem_equal(output.payload, input.payload, input.payload_len);
}

ZTEST(ccsds_space_packet, test_reports_short_buffers)
{
    static const uint8_t payload[] = { 0x5a };
    const struct ccsds_space_packet packet = {
        .version = 0u,
        .type = CCSDS_PACKET_TYPE_TM,
        .secondary_header = false,
        .apid = 2u,
        .sequence_flags = CCSDS_SEQUENCE_UNSEGMENTED,
        .sequence_count = 0u,
        .payload = payload,
        .payload_len = sizeof(payload),
    };
    uint8_t encoded[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + sizeof(payload)];
    size_t encoded_len;

    zassert_equal(ccsds_space_packet_encode(&packet, encoded,
                                            sizeof(encoded) - 1u,
                                            &encoded_len),
                  -ENOSPC);
    zassert_equal(ccsds_space_packet_decode(
                      encoded, CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN - 1u,
                      &(struct ccsds_space_packet){0}),
                  -EINVAL);
}

ZTEST(ccsds_space_packet, test_encoded_length_includes_primary_header)
{
    zassert_equal(ccsds_space_packet_encoded_len(17u),
                  CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + 17u);
}

ZTEST_SUITE(ccsds_space_packet, NULL, NULL, NULL, NULL, NULL);
