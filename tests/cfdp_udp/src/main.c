/* CFDP-over-UDP native_sim peer. Test-only host file and fault hooks. */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nsi_host_trampolines.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "akira_cfdp_service.h"
#include "ccsds_cfdp_pdu.h"
#include "ccsds_profile.h"
#include "ccsds_router.h"
#include "ccsds_space_packet.h"
#include "ccsds_udp.h"

#define CFDP_UDP_MAX_FILE_SIZE 16384u
#define CFDP_UDP_HOST_O_RDONLY 0
#define CFDP_UDP_HOST_O_WRONLY 1
#define CFDP_UDP_HOST_O_TRUNC  512

struct cfdp_udp_file {
    uint8_t data[CFDP_UDP_MAX_FILE_SIZE];
    uint32_t size;
    bool open;
};

static struct cfdp_udp_file source_file;
static struct cfdp_udp_file receive_file;
static const char *output_path;
static const char *injection;
static bool injection_done;
static bool retransmit_observed;
static uint32_t dropped_offset;
static uint32_t nak_sent_count;
static uint32_t nak_received_count;
static uint32_t retransmit_count;

static uint64_t cfdp_udp_now_ms(void *user)
{
    ARG_UNUSED(user);
    return (uint64_t)k_uptime_get();
}

static int load_host_file(const char *path, struct cfdp_udp_file *file)
{
    int fd = nsi_host_open(path, CFDP_UDP_HOST_O_RDONLY);

    if (fd < 0) {
        return -ENOENT;
    }

    file->size = 0u;
    while (file->size < sizeof(file->data)) {
        long rc = nsi_host_read(fd, &file->data[file->size],
                                sizeof(file->data) - file->size);

        if (rc < 0) {
            (void)nsi_host_close(fd);
            return -EIO;
        }
        if (rc == 0) {
            (void)nsi_host_close(fd);
            return 0;
        }
        file->size += (uint32_t)rc;
    }

    {
        uint8_t extra;
        long rc = nsi_host_read(fd, &extra, 1u);

        (void)nsi_host_close(fd);
        return rc == 0 ? 0 : -EFBIG;
    }
}

static int source_open_read(void *user, const char *path, void **handle,
                            uint32_t *size)
{
    struct cfdp_udp_file *file = user;

    ARG_UNUSED(path);
    file->open = true;
    *handle = file;
    *size = file->size;
    return 0;
}

static int file_read(void *user, void *handle, uint32_t offset, uint8_t *buf,
                     size_t len, size_t *nread)
{
    struct cfdp_udp_file *file = handle;
    size_t available;

    ARG_UNUSED(user);
    if (file == NULL || !file->open || offset > file->size) {
        return -EINVAL;
    }
    available = file->size - offset;
    *nread = MIN(len, available);
    memcpy(buf, &file->data[offset], *nread);
    return 0;
}

static int file_close(void *user, void *handle)
{
    struct cfdp_udp_file *file = handle;

    ARG_UNUSED(user);
    if (file == NULL || !file->open) {
        return -EINVAL;
    }
    file->open = false;
    return 0;
}

static int receive_open_write(void *user, const char *path, void **handle)
{
    struct cfdp_udp_file *file = user;

    ARG_UNUSED(path);
    memset(file, 0, sizeof(*file));
    file->open = true;
    *handle = file;
    return 0;
}

static int receive_write(void *user, void *handle, uint32_t offset,
                         const uint8_t *buf, size_t len)
{
    struct cfdp_udp_file *file = handle;
    size_t end = (size_t)offset + len;

    ARG_UNUSED(user);
    if (file == NULL || !file->open || end > sizeof(file->data)) {
        return -EFBIG;
    }
    memcpy(&file->data[offset], buf, len);
    file->size = MAX(file->size, (uint32_t)end);
    return 0;
}

static int receive_commit(void *user, const char *path)
{
    struct cfdp_udp_file *file = user;
    uint32_t written = 0u;
    int fd;

    ARG_UNUSED(path);
    if (output_path == NULL) {
        return -EINVAL;
    }
    fd = nsi_host_open(output_path,
                       CFDP_UDP_HOST_O_WRONLY | CFDP_UDP_HOST_O_TRUNC);
    if (fd < 0) {
        return -EIO;
    }
    while (written < file->size) {
        long rc = nsi_host_write(fd, &file->data[written],
                                 file->size - written);

        if (rc <= 0) {
            (void)nsi_host_close(fd);
            return -EIO;
        }
        written += (uint32_t)rc;
    }
    (void)nsi_host_close(fd);
    return 0;
}

static int receive_discard(void *user, const char *path)
{
    struct cfdp_udp_file *file = user;

    ARG_UNUSED(path);
    memset(file, 0, sizeof(*file));
    return 0;
}

static ccsds_cfdp_filestore_ops_t source_ops = {
    .user = &source_file,
    .open_read = source_open_read,
    .read = file_read,
    .close = file_close,
};

static ccsds_cfdp_filestore_ops_t receive_ops = {
    .user = &receive_file,
    .open_write_tmp = receive_open_write,
    .read = file_read,
    .write = receive_write,
    .close = file_close,
    .commit_tmp = receive_commit,
    .discard_tmp = receive_discard,
};

static bool packet_filedata_offset(const uint8_t *unit, size_t unit_len,
                                   uint32_t *offset)
{
    struct ccsds_space_packet packet;
    ccsds_cfdp_pdu_header_t header;
    ccsds_cfdp_filedata_pdu_t filedata;
    size_t consumed;

    if (ccsds_space_packet_decode(unit, unit_len, &packet) != 0 ||
        ccsds_cfdp_decode_header(packet.payload, packet.payload_len, &header,
                                 &consumed) != CCSDS_CFDP_STATUS_OK ||
        header.pdu_type != CCSDS_CFDP_PDU_TYPE_FILE_DATA ||
        ccsds_cfdp_decode_filedata(packet.payload, packet.payload_len,
                                   &filedata, &consumed) !=
            CCSDS_CFDP_STATUS_OK) {
        return false;
    }
    *offset = filedata.offset;
    return true;
}

static bool packet_is_nak(const uint8_t *unit, size_t unit_len)
{
    struct ccsds_space_packet packet;
    ccsds_cfdp_pdu_header_t header;
    size_t header_len;

    return ccsds_space_packet_decode(unit, unit_len, &packet) == 0 &&
           ccsds_cfdp_decode_header(packet.payload, packet.payload_len,
                                    &header, &header_len) ==
               CCSDS_CFDP_STATUS_OK &&
           header.pdu_type == CCSDS_CFDP_PDU_TYPE_FILE_DIRECTIVE &&
           packet.payload_len > header_len &&
           packet.payload[header_len] == CCSDS_CFDP_DIRECTIVE_NAK;
}

static int test_send_packet(void *user, const uint8_t *unit, size_t unit_len)
{
    uint8_t corrupted[CONFIG_AKIRA_CCSDS_UDP_MAX_UNIT_LEN];
    uint32_t filedata_offset = 0u;
    bool filedata = packet_filedata_offset(unit, unit_len, &filedata_offset);

    ARG_UNUSED(user);
    if (packet_is_nak(unit, unit_len)) {
        nak_sent_count++;
        printk("CFDP_UDP EVENT NAK_SENT\n");
    }
    if (injection_done && !retransmit_observed && filedata &&
        injection != NULL && strcmp(injection, "drop") == 0 &&
        filedata_offset == dropped_offset) {
        retransmit_observed = true;
        retransmit_count++;
        printk("CFDP_UDP EVENT RETRANSMIT offset=%u\n", filedata_offset);
    }
    if (!injection_done && filedata &&
        injection != NULL && strcmp(injection, "drop") == 0) {
        injection_done = true;
        dropped_offset = filedata_offset;
        printk("CFDP_UDP INJECT dropped-file-data offset=%u\n",
               filedata_offset);
        return 0;
    }
    if (!injection_done && filedata &&
        injection != NULL && strcmp(injection, "corrupt") == 0) {
        if (unit_len > sizeof(corrupted)) {
            return -EMSGSIZE;
        }
        memcpy(corrupted, unit, unit_len);
        corrupted[unit_len - 1u] ^= 0x5au;
        injection_done = true;
        printk("CFDP_UDP INJECT corrupted-file-data\n");
        return ccsds_udp_send(NULL, corrupted, unit_len);
    }
    return ccsds_udp_send(NULL, unit, unit_len);
}

static void service_event(void *user, const ccsds_cfdp_event_t *event)
{
    ARG_UNUSED(user);

    if (event->type == CCSDS_CFDP_EVENT_NAK_SENT) {
        nak_sent_count++;
        printk("CFDP_UDP EVENT NAK_SENT transaction=%llu:%llu\n",
               (unsigned long long)event->transaction_id.source_entity_id,
               (unsigned long long)event->transaction_id.transaction_sequence_number);
    } else if (event->type == CCSDS_CFDP_EVENT_NAK_RECV) {
        nak_received_count++;
        printk("CFDP_UDP EVENT NAK_RECV transaction=%llu:%llu\n",
               (unsigned long long)event->transaction_id.source_entity_id,
               (unsigned long long)event->transaction_id.transaction_sequence_number);
    } else if (event->type == CCSDS_CFDP_EVENT_RETRANSMIT) {
        retransmit_count++;
        printk("CFDP_UDP EVENT RETRANSMIT transaction=%llu:%llu\n",
               (unsigned long long)event->transaction_id.source_entity_id,
               (unsigned long long)event->transaction_id.transaction_sequence_number);
    }
}

static int env_u32(const char *name, uint32_t *value)
{
    const char *text = nsi_host_getenv(name);
    char *end;
    unsigned long parsed;

    if (text == NULL || text[0] == '\0') {
        return -EINVAL;
    }
    parsed = strtoul(text, &end, 0);
    if (*end != '\0' || parsed > UINT32_MAX) {
        return -EINVAL;
    }
    *value = (uint32_t)parsed;
    return 0;
}

int main(void)
{
    akira_cfdp_service_config_t config;
    struct ccsds_router router;
    struct ccsds_profile_input input;
    struct akira_cfdp_service_status last = {0};
    uint32_t local;
    uint32_t remote;
    uint32_t apid;
    const char *source_path = nsi_host_getenv("CFDP_SOURCE");
    const char *source_name = nsi_host_getenv("CFDP_SOURCE_NAME");
    const char *destination_name = nsi_host_getenv("CFDP_DEST_NAME");
    const char *mode = nsi_host_getenv("CFDP_MODE");
    uint64_t next_report_ms = 0u;
    int rc;

    output_path = nsi_host_getenv("CFDP_OUTPUT");
    injection = nsi_host_getenv("CFDP_INJECT");
    if (env_u32("CFDP_LOCAL_ENTITY", &local) != 0 ||
        env_u32("CFDP_REMOTE_ENTITY", &remote) != 0 ||
        env_u32("CFDP_APID", &apid) != 0 || local == 0u || remote == 0u ||
        apid == 0u || apid > 0x7ffu) {
        printk("CFDP_UDP FATAL invalid runtime entity/APID configuration\n");
        return 1;
    }

    akira_cfdp_service_config_defaults(&config);
    config.local_entity_id = local;
    config.remote_entity_id = remote;
    config.entity_id_len = 1u;
    config.local_apid = (uint16_t)apid;
    config.remote_apid = (uint16_t)apid;
    config.send_packet = test_send_packet;
    config.now_ms = cfdp_udp_now_ms;
    config.receive_filestore = &receive_ops;
    config.event_cb = service_event;

    ccsds_router_init(&router);
    if (akira_cfdp_service_init(&config) != CCSDS_CFDP_STATUS_OK ||
        akira_cfdp_service_register_rx(&router) != 0) {
        printk("CFDP_UDP FATAL service initialization failed\n");
        return 1;
    }
    ccsds_profile_input_init(&input, &router, NULL);
    rc = ccsds_udp_start(&input);
    if (rc != 0) {
        printk("CFDP_UDP FATAL UDP start failed rc=%d\n", rc);
        return 1;
    }

    printk("CFDP_UDP READY local=%u remote=%u apid=0x%03x udp=%s:%u peer=%s:%u\n",
           local, remote, apid, CONFIG_AKIRA_CCSDS_UDP_LOCAL_IP,
           CONFIG_AKIRA_CCSDS_UDP_LOCAL_PORT,
           CONFIG_AKIRA_CCSDS_UDP_PEER_IP,
           CONFIG_AKIRA_CCSDS_UDP_PEER_PORT);

    if (source_path != NULL) {
        ccsds_cfdp_transaction_id_t id;
        ccsds_cfdp_put_request_t request;

        if (source_name == NULL) {
            source_name = "payload.bin";
        }
        if (destination_name == NULL) {
            destination_name = "received.bin";
        }
        rc = load_host_file(source_path, &source_file);
        if (rc != 0) {
            printk("CFDP_UDP FATAL source load failed rc=%d\n", rc);
            return 1;
        }
        k_sleep(K_MSEC(500));
        request = (ccsds_cfdp_put_request_t){
            .source_path = source_name,
            .destination_path = destination_name,
            .checksum_type = CCSDS_CFDP_CHECKSUM_TYPE_MODULAR,
            .closure_requested = mode == NULL || strcmp(mode, "unack") != 0,
            .acknowledged_mode = mode == NULL || strcmp(mode, "unack") != 0,
        };
        rc = akira_cfdp_service_send_file(&source_ops, &request, &id);
        printk("CFDP_UDP PUT transaction=%llu:%llu size=%u mode=%s rc=%d\n",
               (unsigned long long)id.source_entity_id,
               (unsigned long long)id.transaction_sequence_number,
               source_file.size, request.acknowledged_mode ? "ACK" : "UNACK",
               rc);
    }

    while (true) {
        struct akira_cfdp_service_status status;
        uint64_t now = (uint64_t)k_uptime_get();

        akira_cfdp_service_poll(now);
        akira_cfdp_service_get_status(&status);
        if (status.valid &&
            (!last.valid || status.event_type != last.event_type ||
             status.transaction_id.transaction_sequence_number !=
                 last.transaction_id.transaction_sequence_number ||
             now >= next_report_ms)) {
            printk("CFDP_UDP STATUS transaction=%llu:%llu source=%s dest=%s size=%u checksum=0x%08x checksum=%s status=%s cfdp_status=%s nak_sent=%u nak_recv=%u retransmit=%u\n",
                   (unsigned long long)status.transaction_id.source_entity_id,
                   (unsigned long long)status.transaction_id.transaction_sequence_number,
                   status.source_path, status.destination_path, status.file_size,
                   status.checksum, status.checksum_ok ? "OK" : "NOK",
                   status.event_type == CCSDS_CFDP_EVENT_COMPLETE ? "COMPLETE" : "FAILED",
                   akira_cfdp_service_status_name(status.status), nak_sent_count,
                   nak_received_count, retransmit_count);
            last = status;
            next_report_ms = now + 1000u;
        }
        k_sleep(K_MSEC(50));
    }
    return 0;
}
