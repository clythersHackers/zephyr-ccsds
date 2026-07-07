#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ccsds/ccsds_cfdp_space_packet.h"

struct test_link_endpoint {
    struct ccsds_router *peer_router;
    uint32_t sent_count;
    uint32_t dispatch_failures;
};

struct send_capture {
    uint8_t packet[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + CCSDS_CFDP_MAX_PDU_SIZE];
    size_t packet_len;
    uint32_t count;
};

struct memory_filestore {
    const uint8_t *data;
    uint32_t size;
    uint32_t read_count;
    uint32_t close_count;
};

struct receive_file {
    bool exists;
    bool open;
    char path[CCSDS_CFDP_MAX_FILENAME_LEN + 1u];
    uint8_t data[CCSDS_CFDP_MAX_SEGMENT_SIZE + 16u];
    uint32_t size;
};

struct receive_filestore {
    struct receive_file tmp;
    struct receive_file dst;
    uint32_t write_count;
    uint32_t read_count;
    uint32_t close_count;
    uint32_t commit_count;
    uint32_t discard_count;
};

static int link_send_packet(void *user, const uint8_t *packet,
                            size_t packet_len)
{
    struct test_link_endpoint *endpoint = user;
    int ret;

    if (endpoint == NULL || endpoint->peer_router == NULL ||
        packet == NULL || packet_len == 0u) {
        return -EINVAL;
    }

    endpoint->sent_count++;
    ret = ccsds_router_dispatch_bytes(endpoint->peer_router, packet,
                                      packet_len);
    if (ret != 0) {
        endpoint->dispatch_failures++;
    }

    return ret;
}

static int capture_send_packet(void *user, const uint8_t *packet,
                               size_t packet_len)
{
    struct send_capture *capture = user;

    if (capture == NULL || packet == NULL ||
        packet_len > sizeof(capture->packet)) {
        return -EINVAL;
    }

    memcpy(capture->packet, packet, packet_len);
    capture->packet_len = packet_len;
    capture->count++;
    return 0;
}

static int memory_open_read(void *user, const char *path, void **handle,
                            uint32_t *size)
{
    struct memory_filestore *store = user;

    zassert_not_null(store);
    zassert_equal(strcmp(path, "src.bin"), 0);

    *handle = store;
    *size = store->size;
    return 0;
}

static int memory_read(void *user, void *handle, uint32_t offset, uint8_t *buf,
                       size_t len, size_t *nread)
{
    struct memory_filestore *store = user;
    size_t remaining;

    ARG_UNUSED(user);
    zassert_equal(handle, store);
    zassert_true(offset < store->size);
    zassert_not_null(buf);
    zassert_not_null(nread);

    remaining = store->size - offset;
    *nread = remaining < len ? remaining : len;
    memcpy(buf, &store->data[offset], *nread);
    store->read_count++;
    return 0;
}

static int memory_close(void *user, void *handle)
{
    struct memory_filestore *store = user;

    zassert_equal(handle, store);
    store->close_count++;
    return 0;
}

static int receive_open_write_tmp(void *user, const char *dst_path,
                                  void **handle)
{
    struct receive_filestore *store = user;
    size_t path_len;

    zassert_not_null(store);
    zassert_not_null(dst_path);
    zassert_not_null(handle);

    path_len = strlen(dst_path);
    zassert_true(path_len > 0u);
    zassert_true(path_len <= CCSDS_CFDP_MAX_FILENAME_LEN);

    memset(&store->tmp, 0, sizeof(store->tmp));
    store->tmp.exists = true;
    store->tmp.open = true;
    memcpy(store->tmp.path, dst_path, path_len + 1u);
    *handle = &store->tmp;
    return 0;
}

static int receive_read(void *user, void *handle, uint32_t offset,
                        uint8_t *buf, size_t len, size_t *nread)
{
    struct receive_filestore *store = user;
    struct receive_file *file = handle;
    uint32_t available;

    zassert_not_null(store);
    zassert_not_null(file);
    zassert_not_null(buf);
    zassert_not_null(nread);

    if (offset >= file->size) {
        *nread = 0u;
        return 0;
    }

    available = file->size - offset;
    if (len > available) {
        len = available;
    }

    memcpy(buf, &file->data[offset], len);
    *nread = len;
    store->read_count++;
    return 0;
}

static int receive_write(void *user, void *handle, uint32_t offset,
                         const uint8_t *buf, size_t len)
{
    struct receive_filestore *store = user;
    struct receive_file *file = handle;
    size_t end;

    zassert_not_null(store);
    zassert_not_null(file);
    zassert_not_null(buf);
    zassert_true(file->exists);
    zassert_true(file->open);

    end = (size_t)offset + len;
    zassert_true(end <= sizeof(file->data));

    memcpy(&file->data[offset], buf, len);
    if (end > file->size) {
        file->size = end;
    }
    store->write_count++;
    return 0;
}

static int receive_close(void *user, void *handle)
{
    struct receive_filestore *store = user;
    struct receive_file *file = handle;

    zassert_not_null(store);
    zassert_not_null(file);
    zassert_true(file->open);

    file->open = false;
    store->close_count++;
    return 0;
}

static int receive_commit_tmp(void *user, const char *dst_path)
{
    struct receive_filestore *store = user;

    zassert_not_null(store);
    zassert_not_null(dst_path);
    zassert_true(store->tmp.exists);
    zassert_false(store->tmp.open);
    zassert_equal(strcmp(store->tmp.path, dst_path), 0);

    memset(&store->dst, 0, sizeof(store->dst));
    store->dst.exists = true;
    memcpy(store->dst.path, store->tmp.path, strlen(store->tmp.path) + 1u);
    memcpy(store->dst.data, store->tmp.data, store->tmp.size);
    store->dst.size = store->tmp.size;
    memset(&store->tmp, 0, sizeof(store->tmp));
    store->commit_count++;
    return 0;
}

static int receive_discard_tmp(void *user, const char *dst_path)
{
    struct receive_filestore *store = user;

    zassert_not_null(store);
    zassert_not_null(dst_path);
    zassert_equal(strcmp(store->tmp.path, dst_path), 0);

    memset(&store->tmp, 0, sizeof(store->tmp));
    store->discard_count++;
    return 0;
}

static ccsds_cfdp_filestore_ops_t memory_filestore_ops(
    struct memory_filestore *store)
{
    return (ccsds_cfdp_filestore_ops_t){
        .user = store,
        .open_read = memory_open_read,
        .read = memory_read,
        .close = memory_close,
    };
}

static ccsds_cfdp_filestore_ops_t receive_filestore_ops(
    struct receive_filestore *store)
{
    return (ccsds_cfdp_filestore_ops_t){
        .user = store,
        .open_write_tmp = receive_open_write_tmp,
        .read = receive_read,
        .write = receive_write,
        .close = receive_close,
        .commit_tmp = receive_commit_tmp,
        .discard_tmp = receive_discard_tmp,
    };
}

static ccsds_cfdp_entity_config_t entity_config(uint64_t local_entity_id,
                                                uint64_t remote_entity_id)
{
    return (ccsds_cfdp_entity_config_t){
        .local_entity_id = local_entity_id,
        .remote_entity_id = remote_entity_id,
        .entity_id_len = 1u,
        .transaction_sequence_number_len = 1u,
        .initial_transaction_sequence_number = 3u,
    };
}

static ccsds_cfdp_space_packet_adapter_config_t adapter_config(
    uint64_t remote_entity_id, uint16_t local_apid, uint16_t remote_apid,
    ccsds_cfdp_space_packet_send_cb_t send_packet, void *send_user)
{
    return (ccsds_cfdp_space_packet_adapter_config_t){
        .remote_entity_id = remote_entity_id,
        .local_apid = local_apid,
        .remote_apid = remote_apid,
        .packet_type = CCSDS_PACKET_TYPE_TC,
        .initial_sequence_count = 9u,
        .send_packet = send_packet,
        .send_user = send_user,
    };
}

ZTEST(ccsds_cfdp_space_packet, test_loopback_space_packet_adapter_transfers_file)
{
    struct ccsds_router sender_router;
    struct ccsds_router receiver_router;
    ccsds_cfdp_space_packet_adapter_t sender_adapter;
    ccsds_cfdp_space_packet_adapter_t receiver_adapter;
    ccsds_cfdp_entity_t sender;
    ccsds_cfdp_entity_t receiver;
    struct test_link_endpoint sender_link = {
        .peer_router = &receiver_router,
    };
    struct test_link_endpoint receiver_link = {
        .peer_router = &sender_router,
    };
    const uint8_t file[] = { 0x10u, 0x20u, 0x30u, 0x40u, 0x50u };
    struct memory_filestore source_store = {
        .data = file,
        .size = sizeof(file),
    };
    struct receive_filestore dest_store = { 0 };
    ccsds_cfdp_filestore_ops_t source_ops =
        memory_filestore_ops(&source_store);
    ccsds_cfdp_filestore_ops_t dest_ops = receive_filestore_ops(&dest_store);
    ccsds_cfdp_ut_ops_t sender_ut;
    ccsds_cfdp_ut_ops_t receiver_ut;
    ccsds_cfdp_space_packet_adapter_config_t sender_adapter_config;
    ccsds_cfdp_space_packet_adapter_config_t receiver_adapter_config;
    ccsds_cfdp_entity_config_t sender_config;
    ccsds_cfdp_entity_config_t receiver_config;
    ccsds_cfdp_transaction_id_t id;
    const ccsds_cfdp_put_request_t request = {
        .source_path = "src.bin",
        .destination_path = "dst.bin",
        .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
        .closure_requested = true,
    };

    ccsds_router_init(&sender_router);
    ccsds_router_init(&receiver_router);

    sender_adapter_config = adapter_config(0x34u, 0x101u, 0x102u,
                                           link_send_packet, &sender_link);
    receiver_adapter_config = adapter_config(0x12u, 0x102u, 0x101u,
                                             link_send_packet, &receiver_link);
    zassert_equal(ccsds_cfdp_space_packet_adapter_init(&sender_adapter,
                                                       &sender_adapter_config),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_space_packet_adapter_init(&receiver_adapter,
                                                       &receiver_adapter_config),
                  CCSDS_CFDP_STATUS_OK);

    sender_ut = ccsds_cfdp_space_packet_adapter_ut_ops(&sender_adapter);
    receiver_ut = ccsds_cfdp_space_packet_adapter_ut_ops(&receiver_adapter);
    sender_config = entity_config(0x12u, 0x34u);
    receiver_config = entity_config(0x34u, 0x12u);

    zassert_equal(ccsds_cfdp_entity_init(&sender, &sender_config, &sender_ut),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_entity_init(&receiver, &receiver_config,
                                         &receiver_ut),
                  CCSDS_CFDP_STATUS_OK);

    zassert_ok(ccsds_cfdp_space_packet_adapter_register_rx(
        &sender_adapter, &sender_router, &sender, NULL));
    zassert_ok(ccsds_cfdp_space_packet_adapter_register_rx(
        &receiver_adapter, &receiver_router, &receiver, &dest_ops));

    zassert_equal(ccsds_cfdp_entity_send_file(&sender, &source_ops, &request,
                                              &id),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(id.source_entity_id, 0x12u);
    zassert_equal(id.transaction_sequence_number, 3u);
    zassert_equal(sender_link.sent_count, 3u);
    zassert_equal(receiver_link.sent_count, 1u);
    zassert_equal(sender_link.dispatch_failures, 0u);
    zassert_equal(receiver_link.dispatch_failures, 0u);
    zassert_equal(dest_store.commit_count, 1u);
    zassert_equal(dest_store.discard_count, 0u);
    zassert_true(dest_store.dst.exists);
    zassert_equal(dest_store.dst.size, sizeof(file));
    zassert_mem_equal(dest_store.dst.data, file, sizeof(file));
}

ZTEST(ccsds_cfdp_space_packet, test_malformed_payload_rejected_before_dispatch)
{
    struct ccsds_router router;
    ccsds_cfdp_space_packet_adapter_t adapter;
    ccsds_cfdp_entity_t entity;
    struct send_capture capture = { 0 };
    struct receive_filestore store = { 0 };
    ccsds_cfdp_filestore_ops_t filestore = receive_filestore_ops(&store);
    ccsds_cfdp_ut_ops_t ut;
    ccsds_cfdp_space_packet_adapter_config_t adapter_cfg;
    ccsds_cfdp_entity_config_t cfg;
    const uint8_t bad_payload[] = { 0x00u };
    uint8_t packet_buf[CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN +
                       sizeof(bad_payload)];
    size_t packet_len = 0u;
    const struct ccsds_space_packet packet = {
        .version = 0u,
        .type = CCSDS_PACKET_TYPE_TC,
        .secondary_header = false,
        .apid = 0x222u,
        .sequence_flags = CCSDS_SEQUENCE_UNSEGMENTED,
        .sequence_count = 1u,
        .payload = bad_payload,
        .payload_len = sizeof(bad_payload),
    };

    ccsds_router_init(&router);
    adapter_cfg = adapter_config(0x34u, 0x222u, 0x111u,
                                 capture_send_packet, &capture);
    zassert_equal(ccsds_cfdp_space_packet_adapter_init(&adapter, &adapter_cfg),
                  CCSDS_CFDP_STATUS_OK);
    ut = ccsds_cfdp_space_packet_adapter_ut_ops(&adapter);
    cfg = entity_config(0x12u, 0x34u);
    zassert_equal(ccsds_cfdp_entity_init(&entity, &cfg, &ut),
                  CCSDS_CFDP_STATUS_OK);
    zassert_ok(ccsds_cfdp_space_packet_adapter_register_rx(
        &adapter, &router, &entity, &filestore));

    zassert_ok(ccsds_space_packet_encode(&packet, packet_buf,
                                         sizeof(packet_buf), &packet_len));
    zassert_equal(ccsds_router_dispatch_bytes(&router, packet_buf, packet_len),
                  -EINVAL);
    zassert_equal(store.write_count, 0u);
    zassert_equal(store.commit_count, 0u);
}

ZTEST(ccsds_cfdp_space_packet, test_send_constrains_cfdp_pdu_size)
{
    ccsds_cfdp_space_packet_adapter_t adapter;
    struct send_capture capture = { 0 };
    ccsds_cfdp_ut_ops_t ut;
    ccsds_cfdp_space_packet_adapter_config_t cfg;
    uint8_t pdu[CCSDS_CFDP_MAX_PDU_SIZE + 1u] = { 0x20u };
    struct ccsds_space_packet packet;

    cfg = adapter_config(0x34u, 0x100u, 0x101u, capture_send_packet,
                         &capture);
    zassert_equal(ccsds_cfdp_space_packet_adapter_init(&adapter, &cfg),
                  CCSDS_CFDP_STATUS_OK);
    ut = ccsds_cfdp_space_packet_adapter_ut_ops(&adapter);

    zassert_equal(ccsds_cfdp_space_packet_max_payload_len(&adapter),
                  CCSDS_CFDP_MAX_PDU_SIZE);
    zassert_ok(ut.send_pdu(ut.user, 0x34u, pdu, CCSDS_CFDP_MAX_PDU_SIZE));
    zassert_equal(capture.count, 1u);
    zassert_ok(ccsds_space_packet_decode(capture.packet, capture.packet_len,
                                         &packet));
    zassert_equal(packet.apid, 0x101u);
    zassert_equal(packet.sequence_flags, CCSDS_SEQUENCE_UNSEGMENTED);
    zassert_equal(packet.payload_len, CCSDS_CFDP_MAX_PDU_SIZE);

    zassert_equal(ut.send_pdu(ut.user, 0x34u, pdu, sizeof(pdu)), -EINVAL);
}

ZTEST_SUITE(ccsds_cfdp_space_packet, NULL, NULL, NULL, NULL, NULL);
