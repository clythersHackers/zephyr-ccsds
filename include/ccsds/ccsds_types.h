/**
 * @file ccsds_types.h
 * @brief Shared CCSDS protocol types for AkiraOS.
 */

#ifndef AKIRA_CCSDS_TYPES_H
#define AKIRA_CCSDS_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_AKIRA_CCSDS_ROUTER_MAX_APIDS
#define CONFIG_AKIRA_CCSDS_ROUTER_MAX_APIDS 8
#endif

#ifndef CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN
#define CONFIG_AKIRA_CCSDS_MAX_CLTU_LEN 1024
#endif

#ifndef CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN
#define CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN 1024
#endif

#define CCSDS_APID_MAX 0x07ffu
#define CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN 6u

enum ccsds_packet_type {
    CCSDS_PACKET_TYPE_TM = 0,
    CCSDS_PACKET_TYPE_TC = 1,
};

enum ccsds_sequence_flags {
    CCSDS_SEQUENCE_CONTINUATION = 0,
    CCSDS_SEQUENCE_FIRST = 1,
    CCSDS_SEQUENCE_LAST = 2,
    CCSDS_SEQUENCE_UNSEGMENTED = 3,
};

struct ccsds_const_buffer {
    const uint8_t *data;
    size_t len;
};

struct ccsds_buffer {
    uint8_t *data;
    size_t len;
    size_t cap;
};

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_TYPES_H */
