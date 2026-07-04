#include "ccsds_cfdp_checksum.h"

#include <stdbool.h>
#include <stddef.h>

#include <zephyr/sys/__assert.h>
#include <zephyr/sys/crc.h>

#define CCSDS_CFDP_CRC32C_XOR_OUT 0xffffffffu

static bool checksum_type_is_supported(enum ccsds_cfdp_checksum_type type)
{
    return type == CCSDS_CFDP_CHECKSUM_TYPE_MODULAR ||
           type == CCSDS_CFDP_CHECKSUM_TYPE_CRC32C ||
           type == CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS ||
           type == CCSDS_CFDP_CHECKSUM_TYPE_NULL;
}

static bool update_range_is_valid(uint32_t file_offset, size_t len)
{
    return len <= 1u || (len - 1u) <= ((size_t)UINT32_MAX - file_offset);
}

bool ccsds_cfdp_checksum_supports_out_of_order(
    enum ccsds_cfdp_checksum_type type)
{
    return type == CCSDS_CFDP_CHECKSUM_TYPE_MODULAR ||
           type == CCSDS_CFDP_CHECKSUM_TYPE_NULL;
}

enum ccsds_cfdp_status
ccsds_cfdp_checksum_init(ccsds_cfdp_checksum_state_t *state,
                         enum ccsds_cfdp_checksum_type type)
{
    __ASSERT(state != NULL, "CFDP checksum state is NULL");

    if (!checksum_type_is_supported(type)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM;
    }

    state->type = type;
    state->value = 0u;
    state->next_offset = 0u;
    state->crc_started = false;
    state->deferred = false;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_checksum_update(ccsds_cfdp_checksum_state_t *state,
                           uint32_t file_offset, const uint8_t *data,
                           size_t len)
{
    __ASSERT(state != NULL, "CFDP checksum state is NULL");
    __ASSERT(data != NULL || len == 0u, "CFDP checksum input buffer is NULL");

    if (!checksum_type_is_supported(state->type)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM;
    }

    if (len == 0u) {
        return CCSDS_CFDP_STATUS_OK;
    }

    if (!update_range_is_valid(file_offset, len)) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    switch (state->type) {
    case CCSDS_CFDP_CHECKSUM_TYPE_MODULAR:
        for (size_t i = 0u; i < len; i++) {
            uint8_t byte_lane =
                (uint8_t)((file_offset + (uint32_t)i) & 0x3u);
            uint8_t shift = (uint8_t)((3u - byte_lane) * 8u);

            state->value += (uint32_t)data[i] << shift;
        }
        break;
    case CCSDS_CFDP_CHECKSUM_TYPE_CRC32C:
        if (file_offset != state->next_offset) {
            state->deferred = true;
            break;
        }
        if (!state->deferred) {
            state->value = crc32_c(state->value, data, len,
                                   !state->crc_started, false);
            state->next_offset += (uint32_t)len;
            state->crc_started = true;
        }
        break;
    case CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS:
        if (file_offset != state->next_offset) {
            state->deferred = true;
            break;
        }
        if (!state->deferred) {
            state->value = crc32_ieee_update(state->value, data, len);
            state->next_offset += (uint32_t)len;
        }
        break;
    case CCSDS_CFDP_CHECKSUM_TYPE_NULL:
        break;
    default:
        return CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM;
    }

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_checksum_finish(const ccsds_cfdp_checksum_state_t *state,
                           uint32_t *checksum)
{
    __ASSERT(state != NULL, "CFDP checksum state is NULL");
    __ASSERT(checksum != NULL, "CFDP checksum output is NULL");

    if (!checksum_type_is_supported(state->type)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM;
    }

    switch (state->type) {
    case CCSDS_CFDP_CHECKSUM_TYPE_NULL:
        *checksum = 0u;
        break;
    case CCSDS_CFDP_CHECKSUM_TYPE_CRC32C:
        if (state->deferred) {
            return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
        }
        *checksum = state->crc_started ?
                    (state->value ^ CCSDS_CFDP_CRC32C_XOR_OUT) : 0u;
        break;
    case CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS:
        if (state->deferred) {
            return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
        }
        *checksum = state->value;
        break;
    default:
        *checksum = state->value;
        break;
    }

    return CCSDS_CFDP_STATUS_OK;
}

static bool checksum_type_is_crc(enum ccsds_cfdp_checksum_type type)
{
    return type == CCSDS_CFDP_CHECKSUM_TYPE_CRC32C ||
           type == CCSDS_CFDP_CHECKSUM_TYPE_IEEE_802_3_FCS;
}

enum ccsds_cfdp_status
ccsds_cfdp_checksum_finish_file(const ccsds_cfdp_checksum_state_t *state,
                                ccsds_cfdp_checksum_read_fn read,
                                void *user_data, uint32_t file_size,
                                uint8_t *scratch, size_t scratch_len,
                                uint32_t *checksum)
{
    ccsds_cfdp_checksum_state_t recomputed;
    uint32_t offset = 0u;
    enum ccsds_cfdp_status status;

    __ASSERT(state != NULL, "CFDP checksum state is NULL");
    __ASSERT(checksum != NULL, "CFDP checksum output is NULL");

    if (!checksum_type_is_supported(state->type)) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED_CHECKSUM;
    }

    if (!checksum_type_is_crc(state->type)) {
        return ccsds_cfdp_checksum_finish(state, checksum);
    }

    if (!state->deferred && state->next_offset == file_size) {
        return ccsds_cfdp_checksum_finish(state, checksum);
    }

    __ASSERT(read != NULL, "CFDP checksum read callback is NULL");
    __ASSERT(scratch != NULL || file_size == 0u,
             "CFDP checksum scratch buffer is NULL");
    __ASSERT(scratch_len > 0u || file_size == 0u,
             "CFDP checksum scratch buffer is empty");

    status = ccsds_cfdp_checksum_init(&recomputed, state->type);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    while (offset < file_size) {
        size_t remaining = (size_t)(file_size - offset);
        size_t request_len = remaining < scratch_len ? remaining : scratch_len;
        size_t read_len = 0u;

        status = read(user_data, offset, scratch, request_len, &read_len);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }
        if (read_len == 0u || read_len > request_len ||
            read_len > remaining) {
            return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
        }

        status = ccsds_cfdp_checksum_update(&recomputed, offset, scratch,
                                             read_len);
        if (status != CCSDS_CFDP_STATUS_OK) {
            return status;
        }

        offset += (uint32_t)read_len;
    }

    return ccsds_cfdp_checksum_finish(&recomputed, checksum);
}
