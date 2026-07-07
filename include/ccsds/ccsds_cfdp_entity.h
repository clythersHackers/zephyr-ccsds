/**
 * @file ccsds_cfdp_entity.h
 * @brief Thin CFDP Unitdata Transfer callback boundary for AkiraOS.
 */

#ifndef AKIRA_CCSDS_CFDP_ENTITY_H
#define AKIRA_CCSDS_CFDP_ENTITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ccsds_cfdp_checksum.h"
#include "ccsds_cfdp_filestore.h"
#include "ccsds_cfdp_pdu.h"
#include "ccsds_cfdp_ranges.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ccsds_cfdp_receive_pdu_cb_t)(void *user,
                                            uint64_t source_entity_id,
                                            const uint8_t *pdu,
                                            size_t pdu_len);

struct ccsds_cfdp_ut_ops {
    void *user;
    int (*send_pdu)(void *user, uint64_t dest_entity_id, const uint8_t *pdu,
                    size_t pdu_len);
    uint64_t (*now_ms)(void *user);
};

typedef struct ccsds_cfdp_ut_ops ccsds_cfdp_ut_ops_t;

struct ccsds_cfdp_transaction_id {
    uint64_t source_entity_id;
    uint64_t transaction_sequence_number;
};

typedef struct ccsds_cfdp_transaction_id ccsds_cfdp_transaction_id_t;

struct ccsds_cfdp_entity_config {
    uint64_t local_entity_id;
    uint64_t remote_entity_id;
    uint8_t entity_id_len;
    uint8_t transaction_sequence_number_len;
    uint64_t initial_transaction_sequence_number;
};

typedef struct ccsds_cfdp_entity_config ccsds_cfdp_entity_config_t;

struct ccsds_cfdp_transaction_slot {
    bool active;
    ccsds_cfdp_transaction_id_t id;
    uint64_t peer_entity_id;
    bool metadata_received;
    bool file_handle_open;
    void *file_handle;
    uint32_t file_size;
    uint32_t eof_checksum;
    enum ccsds_cfdp_checksum_type checksum_type;
    enum ccsds_cfdp_transmission_mode transmission_mode;
    ccsds_cfdp_checksum_state_t checksum_state;
    ccsds_cfdp_ranges_t received_ranges;
    char source_path[CCSDS_CFDP_MAX_FILENAME_LEN + 1u];
    char destination_path[CCSDS_CFDP_MAX_FILENAME_LEN + 1u];
    bool closure_requested;
    bool eof_received;
    bool finished_received;
    uint32_t nak_retry_count;
    enum ccsds_cfdp_status finished_status;
};

typedef struct ccsds_cfdp_transaction_slot ccsds_cfdp_transaction_slot_t;

struct ccsds_cfdp_put_request {
    const char *source_path;
    const char *destination_path;
    enum ccsds_cfdp_checksum_type checksum_type;
    bool closure_requested;
    bool acknowledged_mode;
};

typedef struct ccsds_cfdp_put_request ccsds_cfdp_put_request_t;

struct ccsds_cfdp_entity {
    uint64_t local_entity_id;
    uint64_t remote_entity_id;
    uint8_t entity_id_len;
    uint8_t transaction_sequence_number_len;
    uint64_t next_transaction_sequence_number;
    ccsds_cfdp_ut_ops_t ut;
    ccsds_cfdp_transaction_slot_t sender;
    ccsds_cfdp_transaction_slot_t receiver;
    bool sender_completion_available;
    enum ccsds_cfdp_status sender_completion_status;
    uint8_t pdu_buf[CCSDS_CFDP_MAX_PDU_SIZE];
    uint8_t file_segment_buf[CCSDS_CFDP_MAX_SEGMENT_SIZE];
};

typedef struct ccsds_cfdp_entity ccsds_cfdp_entity_t;

enum ccsds_cfdp_status
ccsds_cfdp_entity_init(ccsds_cfdp_entity_t *entity,
                       const ccsds_cfdp_entity_config_t *config,
                       const ccsds_cfdp_ut_ops_t *ut);

enum ccsds_cfdp_status
ccsds_cfdp_entity_create_sender_transaction(
    ccsds_cfdp_entity_t *entity, ccsds_cfdp_transaction_id_t *transaction_id);

enum ccsds_cfdp_status
ccsds_cfdp_entity_send_file(ccsds_cfdp_entity_t *entity,
                            const ccsds_cfdp_filestore_ops_t *filestore,
                            const ccsds_cfdp_put_request_t *request,
                            ccsds_cfdp_transaction_id_t *transaction_id);

enum ccsds_cfdp_status
ccsds_cfdp_entity_receive_pdu(ccsds_cfdp_entity_t *entity,
                              const ccsds_cfdp_filestore_ops_t *filestore,
                              const uint8_t *pdu, size_t pdu_len);

enum ccsds_cfdp_status
ccsds_cfdp_entity_match_or_create_receiver_transaction(
    ccsds_cfdp_entity_t *entity, const uint8_t *pdu, size_t pdu_len,
    ccsds_cfdp_transaction_id_t *transaction_id);

void ccsds_cfdp_entity_release_sender_transaction(ccsds_cfdp_entity_t *entity);

void ccsds_cfdp_entity_release_receiver_transaction(ccsds_cfdp_entity_t *entity);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CFDP_ENTITY_H */
