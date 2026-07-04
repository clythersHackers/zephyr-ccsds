/**
 * @file ccsds_cfdp_ranges.h
 * @brief Fixed-capacity received file range tracking for CFDP.
 */

#ifndef AKIRA_CCSDS_CFDP_RANGES_H
#define AKIRA_CCSDS_CFDP_RANGES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ccsds_cfdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_cfdp_range {
    uint32_t start;
    uint32_t end;
};

typedef struct ccsds_cfdp_range ccsds_cfdp_range_t;

struct ccsds_cfdp_ranges {
    ccsds_cfdp_range_t ranges[CCSDS_CFDP_MAX_NAK_RANGES];
    size_t count;
};

typedef struct ccsds_cfdp_ranges ccsds_cfdp_ranges_t;

/**
 * @brief Initialize caller-owned fixed-capacity range state.
 *
 * @param state Range list to initialize.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_ranges_init(ccsds_cfdp_ranges_t *state);

/**
 * @brief Add a received exclusive-end file range.
 *
 * The list remains sorted and normalized. Overlapping and adjacent ranges are
 * merged. If a disjoint insertion would exceed fixed capacity, the state is
 * left unchanged and BUFFER_TOO_SMALL is returned.
 *
 * @param state Initialized range list.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status ccsds_cfdp_ranges_add(ccsds_cfdp_ranges_t *state,
                                             uint32_t start, uint32_t end);

/**
 * @brief Report whether the requested exclusive-end interval is complete.
 *
 * @param state Initialized range list.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 * @param complete Output completion result.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_ranges_is_complete(const ccsds_cfdp_ranges_t *state,
                              uint32_t start, uint32_t end, bool *complete);

/**
 * @brief Build the missing subranges within an exclusive-end interval.
 *
 * @param state Initialized received range list.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 * @param out_ranges Initialized or uninitialized caller-owned output list.
 *
 * @return CFDP status code.
 */
enum ccsds_cfdp_status
ccsds_cfdp_ranges_missing(const ccsds_cfdp_ranges_t *state, uint32_t start,
                          uint32_t end, ccsds_cfdp_ranges_t *out_ranges);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CFDP_RANGES_H */
