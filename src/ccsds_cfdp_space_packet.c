#include "ccsds_cfdp_space_packet.h"

#include <errno.h>
#include <string.h>

#include <zephyr/sys/__assert.h>

static int cfdp_space_packet_send_pdu(void *user, uint64_t dest_entity_id,
                                      const uint8_t *pdu, size_t pdu_len)
{
    ccsds_cfdp_space_packet_adapter_t *adapter = user;
    struct ccsds_space_packet packet;
    size_t packet_len = 0u;
    int ret;

    if (adapter == NULL || pdu == NULL || pdu_len == 0u ||
        pdu_len > CCSDS_CFDP_MAX_PDU_SIZE ||
        dest_entity_id != adapter->remote_entity_id) {
        return -EINVAL;
    }

    packet = (struct ccsds_space_packet){
        .version = 0u,
        .type = adapter->packet_type,
        .secondary_header = false,
        .apid = adapter->remote_apid,
        .sequence_flags = CCSDS_SEQUENCE_UNSEGMENTED,
        .sequence_count = adapter->sequence_count,
        .payload = pdu,
        .payload_len = pdu_len,
    };

    ret = ccsds_space_packet_encode(&packet, adapter->packet_buf,
                                    sizeof(adapter->packet_buf), &packet_len);
    if (ret != 0) {
        return ret;
    }

    adapter->sequence_count = (adapter->sequence_count + 1u) & 0x3fffu;
    return adapter->send_packet(adapter->send_user, adapter->packet_buf,
                                packet_len);
}

static uint64_t cfdp_space_packet_now_ms(void *user)
{
    ccsds_cfdp_space_packet_adapter_t *adapter = user;

    if (adapter == NULL || adapter->now_ms == NULL) {
        return 0u;
    }

    return adapter->now_ms(adapter->send_user);
}

static int cfdp_space_packet_rx_handler(
    const struct ccsds_space_packet *packet, void *user_data)
{
    ccsds_cfdp_space_packet_adapter_t *adapter = user_data;
    ccsds_cfdp_pdu_header_t header;
    size_t consumed;
    enum ccsds_cfdp_status status;

    if (adapter == NULL || packet == NULL || packet->payload == NULL ||
        adapter->receive_entity == NULL || packet->version != 0u ||
        packet->type != adapter->packet_type || packet->secondary_header ||
        packet->sequence_flags != CCSDS_SEQUENCE_UNSEGMENTED ||
        packet->payload_len == 0u ||
        packet->payload_len > CCSDS_CFDP_MAX_PDU_SIZE) {
        return -EINVAL;
    }

    status = ccsds_cfdp_decode_header(packet->payload, packet->payload_len,
                                      &header, &consumed);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return -EINVAL;
    }

    status = ccsds_cfdp_entity_receive_pdu(adapter->receive_entity,
                                           adapter->receive_filestore,
                                           packet->payload,
                                           packet->payload_len);
    return status == CCSDS_CFDP_STATUS_OK ? 0 : -EINVAL;
}

enum ccsds_cfdp_status ccsds_cfdp_space_packet_adapter_init(
    ccsds_cfdp_space_packet_adapter_t *adapter,
    const ccsds_cfdp_space_packet_adapter_config_t *config)
{
    __ASSERT(adapter != NULL, "CFDP Space Packet adapter is NULL");
    __ASSERT(config != NULL, "CFDP Space Packet adapter config is NULL");

    if (config->local_apid > CCSDS_APID_MAX ||
        config->remote_apid > CCSDS_APID_MAX ||
        config->initial_sequence_count > 0x3fffu ||
        config->send_packet == NULL) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    memset(adapter, 0, sizeof(*adapter));
    adapter->remote_entity_id = config->remote_entity_id;
    adapter->local_apid = config->local_apid;
    adapter->remote_apid = config->remote_apid;
    adapter->packet_type = config->packet_type;
    adapter->sequence_count = config->initial_sequence_count;
    adapter->send_packet = config->send_packet;
    adapter->send_user = config->send_user;
    adapter->now_ms = config->now_ms;

    return CCSDS_CFDP_STATUS_OK;
}

ccsds_cfdp_ut_ops_t ccsds_cfdp_space_packet_adapter_ut_ops(
    ccsds_cfdp_space_packet_adapter_t *adapter)
{
    __ASSERT(adapter != NULL, "CFDP Space Packet adapter is NULL");

    return (ccsds_cfdp_ut_ops_t){
        .user = adapter,
        .send_pdu = cfdp_space_packet_send_pdu,
        .now_ms = adapter->now_ms == NULL ? NULL : cfdp_space_packet_now_ms,
    };
}

int ccsds_cfdp_space_packet_adapter_register_rx(
    ccsds_cfdp_space_packet_adapter_t *adapter, struct ccsds_router *router,
    ccsds_cfdp_entity_t *entity,
    const ccsds_cfdp_filestore_ops_t *filestore)
{
    __ASSERT(adapter != NULL, "CFDP Space Packet adapter is NULL");
    __ASSERT(router != NULL, "CCSDS router is NULL");
    __ASSERT(entity != NULL, "CFDP receive entity is NULL");

    adapter->receive_entity = entity;
    adapter->receive_filestore = filestore;

    return ccsds_router_register_apid(router, adapter->local_apid,
                                      cfdp_space_packet_rx_handler, adapter);
}

size_t ccsds_cfdp_space_packet_max_payload_len(
    const ccsds_cfdp_space_packet_adapter_t *adapter)
{
    __ASSERT(adapter != NULL, "CFDP Space Packet adapter is NULL");

    ARG_UNUSED(adapter);
    return CCSDS_CFDP_MAX_PDU_SIZE;
}
