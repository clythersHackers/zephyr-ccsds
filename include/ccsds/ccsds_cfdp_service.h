/**
 * @file ccsds_cfdp_service.h
 * @brief Instance-based CFDP and Space Packet composition helper.
 */

#ifndef CCSDS_CFDP_SERVICE_H
#define CCSDS_CFDP_SERVICE_H

#include "ccsds_cfdp_entity.h"
#include "ccsds_cfdp_space_packet.h"
#include "ccsds_router.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_cfdp_service_config {
    uint64_t local_entity_id;
    uint64_t remote_entity_id;
    uint8_t entity_id_len;
    uint8_t transaction_sequence_number_len;
    uint64_t initial_transaction_sequence_number;
    uint16_t local_apid;
    uint16_t remote_apid;
    enum ccsds_packet_type packet_type;
    uint16_t initial_packet_sequence_count;
    ccsds_cfdp_space_packet_send_cb_t send_packet;
    void *send_user;
    uint64_t (*now_ms)(void *user);
    const ccsds_cfdp_filestore_ops_t *receive_filestore;
    ccsds_cfdp_event_cb_t event_cb;
    void *event_user;
};

struct ccsds_cfdp_service {
    ccsds_cfdp_entity_t entity;
    ccsds_cfdp_space_packet_adapter_t adapter;
    const ccsds_cfdp_filestore_ops_t *receive_filestore;
};

enum ccsds_cfdp_status
ccsds_cfdp_service_init(struct ccsds_cfdp_service *service,
                        const struct ccsds_cfdp_service_config *config);

int ccsds_cfdp_service_register_rx(struct ccsds_cfdp_service *service,
                                   struct ccsds_router *router);

enum ccsds_cfdp_status
ccsds_cfdp_service_send_file(struct ccsds_cfdp_service *service,
                             const ccsds_cfdp_filestore_ops_t *filestore,
                             const ccsds_cfdp_put_request_t *request,
                             ccsds_cfdp_transaction_id_t *transaction_id);

void ccsds_cfdp_service_poll(struct ccsds_cfdp_service *service,
                             uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* CCSDS_CFDP_SERVICE_H */
