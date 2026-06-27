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

/**
 * @brief Handle one decoded Space Packet selected by APID.
 *
 * @param packet Decoded packet passed by the router.
 * @param user_data Opaque pointer registered with the APID handler.
 *
 * @return 0 on success, or a negative errno from the handler.
 */
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

/**
 * @brief Initialize an APID router table.
 *
 * @param router Router instance to clear.
 *
 * @return 0 on success, or -EINVAL for a NULL router.
 */
int ccsds_router_init(struct ccsds_router *router);

/**
 * @brief Register or replace a handler for one APID.
 *
 * @param router Router instance to update.
 * @param apid CCSDS APID, 0 through CCSDS_APID_MAX.
 * @param handler Callback invoked for packets with @p apid.
 * @param user_data Opaque pointer passed to @p handler.
 *
 * @return 0 on success, -EINVAL for invalid input, or -ENOSPC if the router
 *         table has no free entries.
 */
int ccsds_router_register_apid(struct ccsds_router *router, uint16_t apid,
                               ccsds_apid_handler_t handler,
                               void *user_data);

/**
 * @brief Remove the handler registered for one APID.
 *
 * @param router Router instance to update.
 * @param apid CCSDS APID, 0 through CCSDS_APID_MAX.
 *
 * @return 0 on success, -EINVAL for invalid input, or -ENOENT if @p apid is
 *         not registered.
 */
int ccsds_router_unregister_apid(struct ccsds_router *router, uint16_t apid);

/**
 * @brief Dispatch one decoded Space Packet to its registered APID handler.
 *
 * @param router Router instance to search.
 * @param packet Decoded Space Packet.
 *
 * @return Handler return value on match, -EINVAL for invalid input, or -ENOENT
 *         if no handler is registered for the packet APID.
 */
int ccsds_router_dispatch(struct ccsds_router *router,
                          const struct ccsds_space_packet *packet);

/**
 * @brief Decode encoded Space Packet bytes and dispatch them by APID.
 *
 * @param router Router instance to search.
 * @param packet_bytes Encoded CCSDS Space Packet.
 * @param packet_len Length of @p packet_bytes in bytes.
 *
 * @return Handler return value on match, a decode error, or -ENOENT if no
 *         handler is registered for the decoded APID.
 */
int ccsds_router_dispatch_bytes(struct ccsds_router *router,
                                const uint8_t *packet_bytes,
                                size_t packet_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_ROUTER_H */
