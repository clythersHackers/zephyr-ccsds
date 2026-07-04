#include "ccsds_cfdp_ranges.h"

#include <string.h>

static bool range_is_valid(uint32_t start, uint32_t end)
{
    return start < end;
}

enum ccsds_cfdp_status ccsds_cfdp_ranges_init(ccsds_cfdp_ranges_t *state)
{
    if (state == NULL) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    state->count = 0u;
    memset(state->ranges, 0, sizeof(state->ranges));

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status ccsds_cfdp_ranges_add(ccsds_cfdp_ranges_t *state,
                                             uint32_t start, uint32_t end)
{
    size_t first;
    size_t last;
    size_t remove_count;
    uint32_t merged_start = start;
    uint32_t merged_end = end;

    if (state == NULL || !range_is_valid(start, end) ||
        state->count > CCSDS_CFDP_MAX_NAK_RANGES) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    first = 0u;
    while (first < state->count && state->ranges[first].end < start) {
        first++;
    }

    last = first;
    while (last < state->count && state->ranges[last].start <= end) {
        if (state->ranges[last].start < merged_start) {
            merged_start = state->ranges[last].start;
        }
        if (state->ranges[last].end > merged_end) {
            merged_end = state->ranges[last].end;
        }
        last++;
    }

    remove_count = last - first;
    if (remove_count == 0u && state->count == CCSDS_CFDP_MAX_NAK_RANGES) {
        return CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL;
    }

    if (remove_count == 0u) {
        for (size_t i = state->count; i > first; i--) {
            state->ranges[i] = state->ranges[i - 1u];
        }
        state->count++;
    } else if (remove_count > 1u) {
        for (size_t i = last; i < state->count; i++) {
            state->ranges[first + 1u + i - last] = state->ranges[i];
        }
        state->count -= remove_count - 1u;
    }

    state->ranges[first].start = merged_start;
    state->ranges[first].end = merged_end;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_ranges_is_complete(const ccsds_cfdp_ranges_t *state,
                              uint32_t start, uint32_t end, bool *complete)
{
    if (state == NULL || complete == NULL || !range_is_valid(start, end) ||
        state->count > CCSDS_CFDP_MAX_NAK_RANGES) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    *complete = false;
    for (size_t i = 0u; i < state->count; i++) {
        if (state->ranges[i].start > start) {
            return CCSDS_CFDP_STATUS_OK;
        }
        if (state->ranges[i].start <= start && state->ranges[i].end >= end) {
            *complete = true;
            return CCSDS_CFDP_STATUS_OK;
        }
    }

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_ranges_missing(const ccsds_cfdp_ranges_t *state, uint32_t start,
                          uint32_t end, ccsds_cfdp_ranges_t *out_ranges)
{
    ccsds_cfdp_ranges_t missing;
    uint32_t cursor = start;
    enum ccsds_cfdp_status status;

    if (state == NULL || out_ranges == NULL || !range_is_valid(start, end) ||
        state->count > CCSDS_CFDP_MAX_NAK_RANGES) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    status = ccsds_cfdp_ranges_init(&missing);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    for (size_t i = 0u; i < state->count && cursor < end; i++) {
        const ccsds_cfdp_range_t *received = &state->ranges[i];

        if (received->end <= cursor) {
            continue;
        }
        if (received->start >= end) {
            break;
        }

        if (received->start > cursor) {
            uint32_t missing_end =
                received->start < end ? received->start : end;

            status = ccsds_cfdp_ranges_add(&missing, cursor, missing_end);
            if (status != CCSDS_CFDP_STATUS_OK) {
                return status;
            }
        }

        if (received->end > cursor) {
            cursor = received->end;
        }
    }

    if (cursor < end) {
        status = ccsds_cfdp_ranges_add(&missing, cursor, end);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }
    }

    *out_ranges = missing;

    return CCSDS_CFDP_STATUS_OK;
}
