#include "ccsds_cfdp_service.h"

#include <string.h>

#include <zephyr/sys/__assert.h>

enum ccsds_cfdp_status
ccsds_cfdp_service_init(struct ccsds_cfdp_service *service,
                        const struct ccsds_cfdp_service_config *config)
{
    ccsds_cfdp_space_packet_adapter_config_t adapter_config;
    ccsds_cfdp_entity_config_t entity_config;
    ccsds_cfdp_ut_ops_t ut;
    enum ccsds_cfdp_status status;

    __ASSERT(service != NULL, "CFDP service instance is NULL");
    __ASSERT(config != NULL, "CFDP service configuration is NULL");

    if (config->local_entity_id == 0u || config->remote_entity_id == 0u ||
        config->entity_id_len == 0u ||
        config->transaction_sequence_number_len == 0u ||
        config->local_apid > 0x07ffu || config->remote_apid > 0x07ffu ||
        config->send_packet == NULL || config->receive_filestore == NULL) {
        return CCSDS_CFDP_STATUS_INVALID_ARGUMENT;
    }

    memset(service, 0, sizeof(*service));
    service->receive_filestore = config->receive_filestore;

    adapter_config = (ccsds_cfdp_space_packet_adapter_config_t){
        .remote_entity_id = config->remote_entity_id,
        .local_apid = config->local_apid,
        .remote_apid = config->remote_apid,
        .packet_type = config->packet_type,
        .initial_sequence_count = config->initial_packet_sequence_count,
        .send_packet = config->send_packet,
        .send_user = config->send_user,
        .now_ms = config->now_ms,
    };
    status =
        ccsds_cfdp_space_packet_adapter_init(&service->adapter,
                                             &adapter_config);
    if (status != CCSDS_CFDP_STATUS_OK) {
        return status;
    }

    ut = ccsds_cfdp_space_packet_adapter_ut_ops(&service->adapter);
    entity_config = (ccsds_cfdp_entity_config_t){
        .local_entity_id = config->local_entity_id,
        .remote_entity_id = config->remote_entity_id,
        .entity_id_len = config->entity_id_len,
        .transaction_sequence_number_len =
            config->transaction_sequence_number_len,
        .initial_transaction_sequence_number =
            config->initial_transaction_sequence_number,
        .event_cb = config->event_cb,
        .event_user = config->event_user,
    };

    return ccsds_cfdp_entity_init(&service->entity, &entity_config, &ut);
}

int ccsds_cfdp_service_register_rx(struct ccsds_cfdp_service *service,
                                   struct ccsds_router *router)
{
    __ASSERT(service != NULL, "CFDP service instance is NULL");
    __ASSERT(router != NULL, "CCSDS router is NULL");

    return ccsds_cfdp_space_packet_adapter_register_rx(
        &service->adapter, router, &service->entity,
        service->receive_filestore);
}

enum ccsds_cfdp_status
ccsds_cfdp_service_send_file(struct ccsds_cfdp_service *service,
                             const ccsds_cfdp_filestore_ops_t *filestore,
                             const ccsds_cfdp_put_request_t *request,
                             ccsds_cfdp_transaction_id_t *transaction_id)
{
    __ASSERT(service != NULL, "CFDP service instance is NULL");

    return ccsds_cfdp_entity_send_file(&service->entity, filestore, request,
                                       transaction_id);
}

void ccsds_cfdp_service_poll(struct ccsds_cfdp_service *service,
                             uint64_t now_ms)
{
    __ASSERT(service != NULL, "CFDP service instance is NULL");
    ccsds_cfdp_entity_poll(&service->entity, now_ms);
}
