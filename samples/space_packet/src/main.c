/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <ccsds/ccsds_space_packet.h>

int main(void)
{
	static const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
	static const uint8_t expected[] = {
		0x18, 0x01, 0xc0, 0x2a, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef,
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
	int ret;

	ret = ccsds_space_packet_encode(&input, encoded, sizeof(encoded),
					&encoded_len);
	if (ret != 0 || encoded_len != sizeof(expected) ||
	    memcmp(encoded, expected, sizeof(expected)) != 0) {
		printk("CCSDS Space Packet encode failed\n");
		return -EIO;
	}

	ret = ccsds_space_packet_decode(encoded, encoded_len, &output);
	if (ret != 0 || output.version != input.version ||
	    output.type != input.type ||
	    output.secondary_header != input.secondary_header ||
	    output.apid != input.apid ||
	    output.sequence_flags != input.sequence_flags ||
	    output.sequence_count != input.sequence_count ||
	    output.payload_len != input.payload_len ||
	    memcmp(output.payload, input.payload, input.payload_len) != 0) {
		printk("CCSDS Space Packet decode failed\n");
		return -EIO;
	}

	printk("CCSDS Space Packet round trip OK: APID=%u sequence=%u "
	       "payload=deadbeef\n",
	       output.apid, output.sequence_count);
	return 0;
}
