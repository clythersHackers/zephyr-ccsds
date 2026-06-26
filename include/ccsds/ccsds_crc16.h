/**
 * @file ccsds_crc16.h
 * @brief Shared CCSDS CRC-16 primitive.
 */

#ifndef AKIRA_CCSDS_CRC16_H
#define AKIRA_CCSDS_CRC16_H

#include "ccsds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CCSDS_CRC16_INIT 0xffffu
#define CCSDS_CRC16_POLY 0x1021u
#define CCSDS_CRC16_CHECK_VECTOR 0x29b1u
#define CCSDS_CRC16_LEN 2u

/**
 * @brief Continue a CCSDS CRC-16 calculation.
 *
 * Uses the CCSDS CRC-16 polynomial x^16 + x^12 + x^5 + 1, initial value
 * 0xffff, no reflection, and no final XOR.
 *
 * @param crc Current CRC state, or CCSDS_CRC16_INIT for a new buffer.
 * @param data Input bytes.
 * @param len Number of input bytes.
 *
 * @return Updated CRC state.
 */
uint16_t ccsds_crc16_update(uint16_t crc, const uint8_t *data, size_t len);

/**
 * @brief Compute a CCSDS CRC-16 over one buffer.
 *
 * @param data Input bytes.
 * @param len Number of input bytes.
 *
 * @return CRC value to append to the buffer, most-significant byte first.
 */
uint16_t ccsds_crc16_compute(const uint8_t *data, size_t len);

/**
 * @brief Check a buffer containing data followed by a CCSDS CRC-16.
 *
 * A valid buffer has a zero CRC syndrome when the appended CRC bytes are
 * included in the calculation.
 *
 * @param data Buffer containing payload bytes followed by two CRC bytes.
 * @param len Total buffer length, including the CRC bytes.
 *
 * @return true if the full buffer has a zero CRC syndrome.
 */
bool ccsds_crc16_check(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CRC16_H */
