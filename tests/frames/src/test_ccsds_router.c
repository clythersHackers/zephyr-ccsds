#include <errno.h>

#include <zephyr/ztest.h>

#include "ccsds/ccsds_router.h"

struct router_capture {
    uint16_t apid;
    uint8_t calls;
};

static int capture_packet(const struct ccsds_space_packet *packet,
                          void *user_data)
{
    struct router_capture *capture = user_data;

    capture->apid = packet->apid;
    capture->calls++;
    return 0;
}

ZTEST(ccsds_router, test_register_dispatch_and_unregister)
{
    struct ccsds_router router;
    struct router_capture capture = {0};
    struct ccsds_space_packet packet = {
        .apid = 0x321u,
    };

    ccsds_router_init(&router);
    zassert_ok(ccsds_router_register_apid(&router, packet.apid,
                                          capture_packet, &capture));
    zassert_ok(ccsds_router_dispatch(&router, &packet));
    zassert_equal(capture.calls, 1u);
    zassert_equal(capture.apid, packet.apid);

    zassert_ok(ccsds_router_unregister_apid(&router, packet.apid));
    zassert_equal(ccsds_router_dispatch(&router, &packet), -ENOENT);
}

ZTEST(ccsds_router, test_dispatch_bytes_decodes_space_packet)
{
    static const uint8_t encoded[] = {
        0x03u, 0x21u, 0xc0u, 0x07u, 0x00u, 0x00u, 0xa5u,
    };
    struct ccsds_router router;
    struct router_capture capture = {0};

    ccsds_router_init(&router);
    zassert_ok(ccsds_router_register_apid(&router, 0x321u,
                                          capture_packet, &capture));
    zassert_ok(ccsds_router_dispatch_bytes(&router, encoded,
                                            sizeof(encoded)));
    zassert_equal(capture.calls, 1u);
    zassert_equal(capture.apid, 0x321u);
}

ZTEST(ccsds_router, test_rejects_invalid_registration)
{
    struct ccsds_router router;

    ccsds_router_init(&router);
    zassert_equal(ccsds_router_register_apid(
                      &router, CCSDS_APID_MAX + 1u, capture_packet, NULL),
                  -EINVAL);
}

ZTEST_SUITE(ccsds_router, NULL, NULL, NULL, NULL, NULL);
