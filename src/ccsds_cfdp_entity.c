#include "ccsds_cfdp_entity.h"

#include <string.h>

#include <zephyr/sys/__assert.h>

#define CCSDS_CFDP_MAX_ENCODED_INT_LEN 8u

static bool encoded_int_len_is_valid(uint8_t len, uint8_t max_len)
{
    return len >= 1u && len <= max_len && len <= CCSDS_CFDP_MAX_ENCODED_INT_LEN;
}

static bool value_fits_len(uint64_t value, uint8_t len)
{
    if (len >= CCSDS_CFDP_MAX_ENCODED_INT_LEN) {
        return true;
    }

    return (value >> (len * 8u)) == 0u;
}

static uint64_t transaction_sequence_limit(uint8_t len)
{
    if (len >= CCSDS_CFDP_MAX_ENCODED_INT_LEN) {
        return UINT64_MAX;
    }

    return 1ULL << (len * 8u);
}

static void advance_transaction_sequence_number(ccsds_cfdp_entity_t *entity)
{
    const uint64_t limit =
        transaction_sequence_limit(entity->transaction_sequence_number_len);

    if (limit == UINT64_MAX) {
        entity->next_transaction_sequence_number++;
        return;
    }

    entity->next_transaction_sequence_number =
        (entity->next_transaction_sequence_number + 1u) % limit;
}

static bool transaction_id_matches(const ccsds_cfdp_transaction_id_t *a,
                                   const ccsds_cfdp_transaction_id_t *b)
{
    return a->source_entity_id == b->source_entity_id &&
           a->transaction_sequence_number == b->transaction_sequence_number;
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_init(ccsds_cfdp_entity_t *entity,
                       const ccsds_cfdp_entity_config_t *config,
                       const ccsds_cfdp_ut_ops_t *ut)
{
    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(config != NULL, "CFDP entity config is NULL");
    __ASSERT(ut != NULL, "CFDP UT ops are NULL");

    if (!encoded_int_len_is_valid(config->entity_id_len,
                                  CCSDS_CFDP_MAX_ENTITY_ID_LEN) ||
        !encoded_int_len_is_valid(config->transaction_sequence_number_len,
                                  CCSDS_CFDP_MAX_TRANS_SEQ_LEN) ||
        !value_fits_len(config->local_entity_id, config->entity_id_len) ||
        !value_fits_len(config->remote_entity_id, config->entity_id_len) ||
        !value_fits_len(config->initial_transaction_sequence_number,
                        config->transaction_sequence_number_len) ||
        ut->send_pdu == NULL) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    memset(entity, 0, sizeof(*entity));
    entity->local_entity_id = config->local_entity_id;
    entity->remote_entity_id = config->remote_entity_id;
    entity->entity_id_len = config->entity_id_len;
    entity->transaction_sequence_number_len =
        config->transaction_sequence_number_len;
    entity->next_transaction_sequence_number =
        config->initial_transaction_sequence_number;
    entity->ut = *ut;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_create_sender_transaction(
    ccsds_cfdp_entity_t *entity, ccsds_cfdp_transaction_id_t *transaction_id)
{
    ccsds_cfdp_transaction_id_t allocated;

    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(transaction_id != NULL, "CFDP transaction ID output is NULL");

    if (entity->sender.active) {
        return CCSDS_CFDP_STATUS_TRANSACTION_BUSY;
    }

    allocated.source_entity_id = entity->local_entity_id;
    allocated.transaction_sequence_number =
        entity->next_transaction_sequence_number;
    advance_transaction_sequence_number(entity);

    entity->sender.active = true;
    entity->sender.id = allocated;
    entity->sender.peer_entity_id = entity->remote_entity_id;
    *transaction_id = allocated;

    return CCSDS_CFDP_STATUS_OK;
}

enum ccsds_cfdp_status
ccsds_cfdp_entity_match_or_create_receiver_transaction(
    ccsds_cfdp_entity_t *entity, const uint8_t *pdu, size_t pdu_len,
    ccsds_cfdp_transaction_id_t *transaction_id)
{
    ccsds_cfdp_pdu_header_t header;
    ccsds_cfdp_transaction_id_t incoming;
    size_t consumed;
    enum ccsds_cfdp_status status;

    __ASSERT(entity != NULL, "CFDP entity is NULL");
    __ASSERT(pdu != NULL, "CFDP incoming PDU is NULL");
    __ASSERT(transaction_id != NULL, "CFDP transaction ID output is NULL");

    status = ccsds_cfdp_decode_header(pdu, pdu_len, &header, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    if (header.destination_entity_id != entity->local_entity_id ||
        header.source_entity_id != entity->remote_entity_id ||
        header.entity_id_len != entity->entity_id_len ||
        header.transaction_sequence_number_len !=
            entity->transaction_sequence_number_len ||
        header.direction != CCSDS_CFDP_DIRECTION_TOWARD_RECEIVER) {
        return CCSDS_CFDP_STATUS_UNSUPPORTED;
    }

    incoming.source_entity_id = header.source_entity_id;
    incoming.transaction_sequence_number = header.transaction_sequence_number;

    if (entity->receiver.active) {
        if (!transaction_id_matches(&entity->receiver.id, &incoming)) {
            return CCSDS_CFDP_STATUS_TRANSACTION_BUSY;
        }

        *transaction_id = entity->receiver.id;
        return CCSDS_CFDP_STATUS_OK;
    }

    entity->receiver.active = true;
    entity->receiver.id = incoming;
    entity->receiver.peer_entity_id = header.source_entity_id;
    *transaction_id = incoming;

    return CCSDS_CFDP_STATUS_OK;
}

void ccsds_cfdp_entity_release_sender_transaction(ccsds_cfdp_entity_t *entity)
{
    __ASSERT(entity != NULL, "CFDP entity is NULL");

    memset(&entity->sender, 0, sizeof(entity->sender));
}

void ccsds_cfdp_entity_release_receiver_transaction(ccsds_cfdp_entity_t *entity)
{
    __ASSERT(entity != NULL, "CFDP entity is NULL");

    memset(&entity->receiver, 0, sizeof(entity->receiver));
}
