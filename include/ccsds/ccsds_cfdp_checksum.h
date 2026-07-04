/**
 * @file ccsds_cfdp_checksum.h
 * @brief CCSDS CFDP file checksum helpers for the AkiraOS subset.
 */

#ifndef AKIRA_CCSDS_CFDP_CHECKSUM_H
#define AKIRA_CCSDS_CFDP_CHECKSUM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ccsds_cfdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_cfdp_checksum_state {
    enum ccsds_cfdp_checksum_type type;
    uint32_t value;
    uint32_t next_offset;
    bool crc_started;
    bool deferred;
};

typedef struct ccsds_cfdp_checksum_state ccsds_cfdp_checksum_state_t;

/**
 * @brief Read bytes from a completed file for deferred checksum calculation.
 *
 * @param user_data Caller context for the backing store.
 * @param offset File offset to read from.
 * @param buf Caller-provided destination buffer.
 * @param cap Capacity of @p buf in bytes.
 * @param len Output number of bytes read.
 *
 * @return CFDP status code.
 */
typedef enum ccsds_cfdp_status (*ccsds_cfdp_checksum_read_fn)(
    void *user_data, uint32_t offset, uint8_t *buf, size_t cap, size_t *len);

/**
 * @brief Return whether a checksum type can be fully accumulated from
 *        out-of-order file data segments.
 *
 * Modular checksum is file-offset based and can be updated as File Data PDUs
 * arrive. CRC-based checksum types are byte-stream algorithms; update() accepts
 * out-of-order CRC segments but records that finish_file() must later read the
 * completed file from offset zero.
 *
 * @param type CFDP checksum algorithm identifier.
 *
 * @return true when arbitrary file offsets are accumulated without deferred
 *         file reading.
 */
bool ccsds_cfdp_checksum_supports_out_of_order(
    enum ccsds_cfdp_checksum_type type);

/**
 * @brief Initialize caller-owned CFDP checksum state.
 *
 * @param state Checksum state to initialize.
 * @param type CFDP checksum algorithm identifier.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_checksum_init(ccsds_cfdp_checksum_state_t *state,
                         enum ccsds_cfdp_checksum_type type);

/**
 * @brief Add file data bytes to a CFDP checksum.
 *
 * The modular checksum accepts arbitrary file offsets. CRC-based checksum
 * types are calculated incrementally while updates arrive in order; when a CRC
 * update arrives out of order, the state records that finalization must read
 * the completed stored file with ccsds_cfdp_checksum_finish_file().
 *
 * @param state Initialized checksum state.
 * @param file_offset Offset of @p data in the transmitted file.
 * @param data File data bytes, or NULL when @p len is zero.
 * @param len Number of file data bytes.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_checksum_update(ccsds_cfdp_checksum_state_t *state,
                           uint32_t file_offset, const uint8_t *data,
                           size_t len);

/**
 * @brief Return the final CFDP checksum value.
 *
 * @param state Initialized checksum state.
 * @param checksum Output checksum value.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_checksum_finish(const ccsds_cfdp_checksum_state_t *state,
                           uint32_t *checksum);

/**
 * @brief Return the final checksum, reading a completed file when required.
 *
 * CRC-based checksum types can only be calculated over a contiguous byte
 * stream. If update() observed out-of-order CRC data, or if the streamed byte
 * count does not match @p file_size, this function recomputes the checksum by
 * reading the completed file from offset zero. Modular and null checksum types
 * do not require @p read or @p scratch.
 *
 * @param state Initialized checksum state.
 * @param read Callback for reading completed file bytes when required.
 * @param user_data Caller context passed to @p read.
 * @param file_size Completed file size in bytes.
 * @param scratch Caller-provided working buffer used for file reads.
 * @param scratch_len Capacity of @p scratch in bytes.
 * @param checksum Output checksum value.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_checksum_finish_file(const ccsds_cfdp_checksum_state_t *state,
                                ccsds_cfdp_checksum_read_fn read,
                                void *user_data, uint32_t file_size,
                                uint8_t *scratch, size_t scratch_len,
                                uint32_t *checksum);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CFDP_CHECKSUM_H */
