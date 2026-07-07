/**
 * @file ccsds_cfdp_space_packet.h
 * @brief CCSDS Space Packet Unitdata Transfer adapter for CFDP.
 */

#ifndef AKIRA_CCSDS_CFDP_SPACE_PACKET_H
#define AKIRA_CCSDS_CFDP_SPACE_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "ccsds_cfdp_entity.h"
#include "ccsds_router.h"
#include "ccsds_space_packet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*ccsds_cfdp_space_packet_send_cb_t)(void *user,
                                                 const uint8_t *packet,
                                                 size_t packet_len);

struct ccsds_cfdp_space_packet_adapter_config {
    uint64_t remote_entity_id;
    uint16_t local_apid;
    uint16_t remote_apid;
    enum ccsds_packet_type packet_type;
    uint16_t initial_sequence_count;
    ccsds_cfdp_space_packet_send_cb_t send_packet;
    void *send_user;
    uint64_t (*now_ms)(void *user);
};

typedef struct ccsds_cfdp_space_packet_adapter_config
    ccsds_cfdp_space_packet_adapter_config_t;

struct ccsds_cfdp_space_packet_adapter {
    uint64_t remote_entity_id;
    uint16_t local_apid;
    uint16_t remote_apid;
    enum ccsds_packet_type packet_type;
    uint16_t sequence_count;
    ccsds_cfdp_space_packet_send_cb_t send_packet;
    void *send_user;
    uint64_t (*now_ms)(void *user);
    ccsds_cfdp_entity_t *receive_entity;
    const ccsds_cfdp_filestore_ops_t *receive_filestore;
    uint8_t packet_buf[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN +
                       CCSDS_CFDP_MAX_PDU_SIZE];
};

typedef struct ccsds_cfdp_space_packet_adapter
    ccsds_cfdp_space_packet_adapter_t;

enum ccsds_cfdp_status ccsds_cfdp_space_packet_adapter_init(
    ccsds_cfdp_space_packet_adapter_t *adapter,
    const ccsds_cfdp_space_packet_adapter_config_t *config);

ccsds_cfdp_ut_ops_t ccsds_cfdp_space_packet_adapter_ut_ops(
    ccsds_cfdp_space_packet_adapter_t *adapter);

int ccsds_cfdp_space_packet_adapter_register_rx(
    ccsds_cfdp_space_packet_adapter_t *adapter, struct ccsds_router *router,
    ccsds_cfdp_entity_t *entity,
    const ccsds_cfdp_filestore_ops_t *filestore);

size_t ccsds_cfdp_space_packet_max_payload_len(
    const ccsds_cfdp_space_packet_adapter_t *adapter);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CFDP_SPACE_PACKET_H */
