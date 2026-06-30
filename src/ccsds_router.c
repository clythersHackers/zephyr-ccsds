#include "ccsds_router.h"

#include <errno.h>
#include <string.h>

#include <zephyr/sys/__assert.h>

int ccsds_router_init(struct ccsds_router *router)
{
    __ASSERT(router != NULL, "CCSDS router is NULL");

    memset(router, 0, sizeof(*router));
    return 0;
}

int ccsds_router_register_apid(struct ccsds_router *router, uint16_t apid,
                               ccsds_apid_handler_t handler,
                               void *user_data)
{
    __ASSERT(router != NULL, "CCSDS router is NULL");
    __ASSERT(handler != NULL, "CCSDS APID handler is NULL");

    if (apid > CCSDS_APID_MAX) {
        return -EINVAL;
    }

    for (size_t i = 0; i < CONFIG_AKIRA_CCSDS_ROUTER_MAX_APIDS; i++) {
        if (router->entries[i].active && router->entries[i].apid == apid) {
            router->entries[i].handler = handler;
            router->entries[i].user_data = user_data;
            return 0;
        }
    }

    for (size_t i = 0; i < CONFIG_AKIRA_CCSDS_ROUTER_MAX_APIDS; i++) {
        if (!router->entries[i].active) {
            router->entries[i].apid = apid;
            router->entries[i].handler = handler;
            router->entries[i].user_data = user_data;
            router->entries[i].active = true;
            return 0;
        }
    }

    return -ENOSPC;
}

int ccsds_router_unregister_apid(struct ccsds_router *router, uint16_t apid)
{
    __ASSERT(router != NULL, "CCSDS router is NULL");

    if (apid > CCSDS_APID_MAX) {
        return -EINVAL;
    }

    for (size_t i = 0; i < CONFIG_AKIRA_CCSDS_ROUTER_MAX_APIDS; i++) {
        if (router->entries[i].active && router->entries[i].apid == apid) {
            memset(&router->entries[i], 0, sizeof(router->entries[i]));
            return 0;
        }
    }

    return -ENOENT;
}

int ccsds_router_dispatch(struct ccsds_router *router,
                          const struct ccsds_space_packet *packet)
{
    __ASSERT(router != NULL, "CCSDS router is NULL");
    __ASSERT(packet != NULL, "CCSDS packet is NULL");

    if (packet->apid > CCSDS_APID_MAX) {
        return -EINVAL;
    }

    for (size_t i = 0; i < CONFIG_AKIRA_CCSDS_ROUTER_MAX_APIDS; i++) {
        struct ccsds_router_entry *entry = &router->entries[i];

        if (entry->active && entry->apid == packet->apid) {
            return entry->handler(packet, entry->user_data);
        }
    }

    return -ENOENT;
}

int ccsds_router_dispatch_bytes(struct ccsds_router *router,
                                const uint8_t *packet_bytes,
                                size_t packet_len)
{
    struct ccsds_space_packet packet;
    int ret = ccsds_space_packet_decode(packet_bytes, packet_len, &packet);

    if (ret != 0) {
        return ret;
    }

    return ccsds_router_dispatch(router, &packet);
}
