/**
 * @file ccsds_router.h
 * @brief Fixed-size APID router for decoded CCSDS Space Packets.
 */

#ifndef AKIRA_CCSDS_ROUTER_H
#define AKIRA_CCSDS_ROUTER_H

#include "ccsds_space_packet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*ccsds_apid_handler_t)(const struct ccsds_space_packet *packet,
                                    void *user_data);

struct ccsds_router_entry {
    uint16_t apid;
    ccsds_apid_handler_t handler;
    void *user_data;
    bool active;
};

struct ccsds_router {
    struct ccsds_router_entry entries[CONFIG_AKIRA_CCSDS_ROUTER_MAX_APIDS];
};

int ccsds_router_init(struct ccsds_router *router);

int ccsds_router_register_apid(struct ccsds_router *router, uint16_t apid,
                               ccsds_apid_handler_t handler,
                               void *user_data);

int ccsds_router_unregister_apid(struct ccsds_router *router, uint16_t apid);

int ccsds_router_dispatch(struct ccsds_router *router,
                          const struct ccsds_space_packet *packet);

int ccsds_router_dispatch_bytes(struct ccsds_router *router,
                                const uint8_t *packet_bytes,
                                size_t packet_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_ROUTER_H */
