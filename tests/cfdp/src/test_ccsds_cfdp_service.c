#include <string.h>

#include <zephyr/ztest.h>

#include "ccsds_cfdp_service.h"

struct service_fixture {
    struct ccsds_cfdp_service service;
    struct ccsds_router router;
    ccsds_cfdp_filestore_ops_t filestore;
    uint32_t sent;
};

static int send_packet(void *user, const uint8_t *packet, size_t packet_len)
{
    struct service_fixture *fixture = user;

    zassert_not_null(packet);
    zassert_true(packet_len >= CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN);
    fixture->sent++;
    return 0;
}

static int open_read(void *user, const char *path, void **handle,
                     uint32_t *size)
{
    static uint8_t data[] = {1u, 2u, 3u};

    ARG_UNUSED(user);
    ARG_UNUSED(path);
    *handle = data;
    *size = sizeof(data);
    return 0;
}

static int read_file(void *user, void *handle, uint32_t offset, uint8_t *buf,
                     size_t len, size_t *nread)
{
    static const uint8_t data[] = {1u, 2u, 3u};

    ARG_UNUSED(user);
    ARG_UNUSED(handle);
    *nread = MIN(len, sizeof(data) - offset);
    memcpy(buf, &data[offset], *nread);
    return 0;
}

static int close_file(void *user, void *handle)
{
    ARG_UNUSED(user);
    ARG_UNUSED(handle);
    return 0;
}

static void init_fixture(struct service_fixture *fixture, uint64_t local,
                         uint64_t remote, uint16_t apid)
{
    struct ccsds_cfdp_service_config config;

    memset(fixture, 0, sizeof(*fixture));
    fixture->filestore = (ccsds_cfdp_filestore_ops_t){
        .open_read = open_read,
        .read = read_file,
        .close = close_file,
    };
    config = (struct ccsds_cfdp_service_config){
        .local_entity_id = local,
        .remote_entity_id = remote,
        .entity_id_len = 1u,
        .transaction_sequence_number_len = 1u,
        .initial_transaction_sequence_number = 1u,
        .local_apid = apid,
        .remote_apid = apid,
        .packet_type = CCSDS_PACKET_TYPE_TC,
        .send_packet = send_packet,
        .send_user = fixture,
        .receive_filestore = &fixture->filestore,
    };
    ccsds_router_init(&fixture->router);
    zassert_equal(ccsds_cfdp_service_init(&fixture->service, &config),
                  CCSDS_CFDP_STATUS_OK);
    zassert_ok(
        ccsds_cfdp_service_register_rx(&fixture->service, &fixture->router));
}

ZTEST(ccsds_cfdp_service, test_two_services_own_independent_state)
{
    struct service_fixture a;
    struct service_fixture b;
    const ccsds_cfdp_put_request_t request = {
        .source_path = "source.bin",
        .destination_path = "destination.bin",
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
    };
    ccsds_cfdp_transaction_id_t a_id;
    ccsds_cfdp_transaction_id_t b_id;

    init_fixture(&a, 1u, 2u, 0x340u);
    init_fixture(&b, 9u, 10u, 0x341u);

    zassert_equal(ccsds_cfdp_service_send_file(
                      &a.service, &a.filestore, &request, &a_id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_service_send_file(
                      &b.service, &b.filestore, &request, &b_id),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(a_id.source_entity_id, 1u);
    zassert_equal(b_id.source_entity_id, 9u);
    zassert_equal(a.sent, 3u);
    zassert_equal(b.sent, 3u);
    zassert_not_equal(&a.service.entity, &b.service.entity);
    zassert_not_equal(&a.service.adapter, &b.service.adapter);
}

ZTEST_SUITE(ccsds_cfdp_service, NULL, NULL, NULL, NULL, NULL);
