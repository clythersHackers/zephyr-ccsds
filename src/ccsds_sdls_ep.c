#include "ccsds_sdls.h"

#include <string.h>

#include <psa/crypto.h>
#include <psa/crypto_values.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/toolchain.h>

#define EP_TAG_REPLY BIT(7)
#define EP_TAG_USER BIT(6)
#define EP_TAG_SERVICE_MASK (BIT(5) | BIT(4))
#define EP_TAG_PROCEDURE_MASK 0x0fu

static void wipe(void *data, size_t len)
{
    volatile uint8_t *p = data;

    while (len-- != 0u) {
        *p++ = 0u;
    }
}

static size_t pdu_size(size_t data_len)
{
    return CCSDS_SDLS_EP_HEADER_LEN + data_len;
}

static bool procedure_supported(uint8_t type, uint8_t service_group,
                                uint8_t procedure)
{
    if (service_group == CCSDS_SDLS_EP_KEY_MANAGEMENT) {
        return procedure >= CCSDS_SDLS_EP_OTAR &&
               procedure <= CCSDS_SDLS_EP_KEY_VERIFICATION &&
               (type == CCSDS_SDLS_EP_COMMAND ||
                procedure == CCSDS_SDLS_EP_KEY_VERIFICATION);
    }
    if (service_group == CCSDS_SDLS_EP_SA_MANAGEMENT) {
        bool known = procedure == CCSDS_SDLS_EP_READ_ARSN ||
                     procedure == CCSDS_SDLS_EP_SET_ARSN_WINDOW ||
                     procedure == CCSDS_SDLS_EP_REKEY_SA ||
                     procedure == CCSDS_SDLS_EP_EXPIRE_SA ||
                     procedure == CCSDS_SDLS_EP_SET_ARSN ||
                     procedure == CCSDS_SDLS_EP_START_SA ||
                     procedure == CCSDS_SDLS_EP_STOP_SA ||
                     procedure == CCSDS_SDLS_EP_SA_STATUS;
        bool reply = procedure == CCSDS_SDLS_EP_READ_ARSN ||
                     procedure == CCSDS_SDLS_EP_SA_STATUS;

        return known && (type == CCSDS_SDLS_EP_COMMAND ||
                         (type == CCSDS_SDLS_EP_REPLY && reply));
    }
    return service_group == CCSDS_SDLS_EP_SECURITY_MONITORING &&
           procedure == CCSDS_SDLS_EP_ALARM_FLAG_RESET &&
           type == CCSDS_SDLS_EP_COMMAND;
}

static void encode_header(uint8_t type, uint8_t service_group,
                          uint8_t procedure, size_t data_len, uint8_t *out)
{
    __ASSERT(type <= CCSDS_SDLS_EP_REPLY, "invalid SDLS EP PDU type");
    __ASSERT(procedure_supported(type, service_group, procedure),
             "invalid SDLS EP procedure");
    __ASSERT(data_len <= UINT16_MAX / 8u, "SDLS EP bit length overflows");

    out[0] = (type == CCSDS_SDLS_EP_REPLY ? EP_TAG_REPLY : 0u) |
             ((service_group << 4) & EP_TAG_SERVICE_MASK) | procedure;
    sys_put_be16((uint16_t)(data_len * 8u), out + 1u);
}

int ccsds_sdls_ep_pdu_decode(const uint8_t *encoded, size_t encoded_len,
                             struct ccsds_sdls_ep_pdu *pdu)
{
    size_t data_len;
    uint16_t bit_len;
    uint8_t tag;
    uint8_t procedure;
    uint8_t service_group;
    uint8_t type;

    __ASSERT(encoded != NULL, "SDLS EP input is NULL");
    __ASSERT(pdu != NULL, "SDLS EP output is NULL");

    if (encoded_len < CCSDS_SDLS_EP_HEADER_LEN) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    tag = encoded[0];
    if ((tag & EP_TAG_USER) != 0u) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    service_group = (tag & EP_TAG_SERVICE_MASK) >> 4;
    procedure = tag & EP_TAG_PROCEDURE_MASK;
    type = (tag & EP_TAG_REPLY) != 0u ? CCSDS_SDLS_EP_REPLY
                                      : CCSDS_SDLS_EP_COMMAND;
    if (!procedure_supported(type, service_group, procedure)) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }

    bit_len = sys_get_be16(encoded + 1u);
    if ((bit_len & 7u) != 0u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    data_len = bit_len / 8u;
    if (data_len > SIZE_MAX - CCSDS_SDLS_EP_HEADER_LEN ||
        encoded_len != pdu_size(data_len)) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    if (encoded_len > CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX &&
        encoded_len > CCSDS_SDLS_EP_OTAR_PDU_MAX) {
        return CCSDS_SDLS_ERR_CAPACITY;
    }

    pdu->data = encoded + CCSDS_SDLS_EP_HEADER_LEN;
    pdu->data_len = data_len;
    pdu->service_group = service_group;
    pdu->procedure = procedure;
    pdu->type = type;
    return 0;
}

void ccsds_sdls_ep_otar_encode(const struct ccsds_sdls_ep_otar *otar,
                               uint8_t *out, size_t out_capacity)
{
    size_t clear_len;
    size_t data_len;
    size_t offset;

    __ASSERT(otar != NULL, "SDLS EP OTAR input is NULL");
    __ASSERT(out != NULL, "SDLS EP OTAR output is NULL");
    __ASSERT(otar->key_count > 0u &&
                 otar->key_count <= CCSDS_SDLS_EP_MAX_OTAR_KEYS,
             "invalid SDLS EP OTAR key count");
    clear_len = otar->key_count * CCSDS_SDLS_EP_OTAR_BLOCK_LEN;
    data_len = 2u + CCSDS_SDLS_IV_LEN + clear_len + CCSDS_SDLS_TAG_LEN;
    __ASSERT(out_capacity >= pdu_size(data_len),
             "SDLS EP OTAR output is too small");

    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_KEY_MANAGEMENT,
                  CCSDS_SDLS_EP_OTAR, data_len, out);
    sys_put_be16(otar->master_key_id, out + CCSDS_SDLS_EP_HEADER_LEN);
    offset = CCSDS_SDLS_EP_HEADER_LEN + 2u;
    memcpy(out + offset, otar->iv, CCSDS_SDLS_IV_LEN);
    offset += CCSDS_SDLS_IV_LEN;
    memcpy(out + offset, otar->encrypted_key_blocks, clear_len);
    offset += clear_len;
    memcpy(out + offset, otar->tag, CCSDS_SDLS_TAG_LEN);
}

int ccsds_sdls_ep_otar_decode(const uint8_t *encoded, size_t encoded_len,
                              struct ccsds_sdls_ep_otar *otar)
{
    struct ccsds_sdls_ep_pdu pdu;
    size_t encrypted_len;
    size_t key_count;
    size_t offset;
    int ret;

    __ASSERT(otar != NULL, "SDLS EP OTAR output is NULL");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }
    if (pdu.type != CCSDS_SDLS_EP_COMMAND ||
        pdu.service_group != CCSDS_SDLS_EP_KEY_MANAGEMENT ||
        pdu.procedure != CCSDS_SDLS_EP_OTAR) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    if (pdu.data_len < 2u + CCSDS_SDLS_IV_LEN + CCSDS_SDLS_TAG_LEN +
                           CCSDS_SDLS_EP_OTAR_BLOCK_LEN) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    encrypted_len = pdu.data_len - 2u - CCSDS_SDLS_IV_LEN - CCSDS_SDLS_TAG_LEN;
    if (encrypted_len % CCSDS_SDLS_EP_OTAR_BLOCK_LEN != 0u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    key_count = encrypted_len / CCSDS_SDLS_EP_OTAR_BLOCK_LEN;
    if (key_count > CCSDS_SDLS_EP_MAX_OTAR_KEYS) {
        return CCSDS_SDLS_ERR_CAPACITY;
    }

    otar->master_key_id = sys_get_be16(pdu.data);
    offset = 2u;
    memcpy(otar->iv, pdu.data + offset, CCSDS_SDLS_IV_LEN);
    offset += CCSDS_SDLS_IV_LEN;
    memcpy(otar->encrypted_key_blocks, pdu.data + offset, encrypted_len);
    offset += encrypted_len;
    memcpy(otar->tag, pdu.data + offset, CCSDS_SDLS_TAG_LEN);
    otar->key_count = key_count;
    return 0;
}

void ccsds_sdls_ep_key_command_encode(
    enum ccsds_sdls_ep_procedure procedure,
    const struct ccsds_sdls_ep_key_command *command, uint8_t *out,
    size_t out_capacity)
{
    size_t data_len;

    __ASSERT(procedure == CCSDS_SDLS_EP_KEY_ACTIVATION ||
                 procedure == CCSDS_SDLS_EP_KEY_DEACTIVATION,
             "invalid SDLS EP key command procedure");
    __ASSERT(command != NULL, "SDLS EP key command is NULL");
    __ASSERT(out != NULL, "SDLS EP key command output is NULL");
    __ASSERT(command->key_count > 0u &&
                 command->key_count <= CCSDS_SDLS_EP_MAX_RECIPIENTS,
             "invalid SDLS EP key recipient count");
    data_len = command->key_count * 2u;
    __ASSERT(out_capacity >= pdu_size(data_len),
             "SDLS EP key command output is too small");

    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_KEY_MANAGEMENT,
                  procedure, data_len, out);
    for (size_t i = 0u; i < command->key_count; i++) {
        sys_put_be16(command->key_ids[i],
                     out + CCSDS_SDLS_EP_HEADER_LEN + i * 2u);
    }
}

int ccsds_sdls_ep_key_command_decode(
    const uint8_t *encoded, size_t encoded_len,
    enum ccsds_sdls_ep_procedure expected_procedure,
    struct ccsds_sdls_ep_key_command *command)
{
    struct ccsds_sdls_ep_pdu pdu;
    size_t key_count;
    int ret;

    __ASSERT(command != NULL, "SDLS EP key command output is NULL");
    __ASSERT(expected_procedure == CCSDS_SDLS_EP_KEY_ACTIVATION ||
                 expected_procedure == CCSDS_SDLS_EP_KEY_DEACTIVATION,
             "invalid expected SDLS EP key procedure");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }
    if (pdu.type != CCSDS_SDLS_EP_COMMAND ||
        pdu.service_group != CCSDS_SDLS_EP_KEY_MANAGEMENT ||
        pdu.procedure != expected_procedure) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    if (pdu.data_len == 0u || (pdu.data_len & 1u) != 0u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    key_count = pdu.data_len / 2u;
    if (key_count > CCSDS_SDLS_EP_MAX_RECIPIENTS) {
        return CCSDS_SDLS_ERR_CAPACITY;
    }
    for (size_t i = 0u; i < key_count; i++) {
        command->key_ids[i] = sys_get_be16(pdu.data + i * 2u);
    }
    command->key_count = key_count;
    return 0;
}

void ccsds_sdls_ep_verify_command_encode(
    const struct ccsds_sdls_ep_verify_command *command, uint8_t *out,
    size_t out_capacity)
{
    size_t data_len;
    size_t offset = CCSDS_SDLS_EP_HEADER_LEN;

    __ASSERT(command != NULL, "SDLS EP verification command is NULL");
    __ASSERT(out != NULL, "SDLS EP verification command output is NULL");
    __ASSERT(command->key_count > 0u &&
                 command->key_count <= CCSDS_SDLS_EP_MAX_RECIPIENTS,
             "invalid SDLS EP verification recipient count");
    data_len = command->key_count * CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN;
    __ASSERT(out_capacity >= pdu_size(data_len),
             "SDLS EP verification command output is too small");

    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_KEY_MANAGEMENT,
                  CCSDS_SDLS_EP_KEY_VERIFICATION, data_len, out);
    for (size_t i = 0u; i < command->key_count; i++) {
        sys_put_be16(command->entries[i].key_id, out + offset);
        offset += 2u;
        memcpy(out + offset, command->entries[i].challenge,
               CCSDS_SDLS_EP_CHALLENGE_LEN);
        offset += CCSDS_SDLS_EP_CHALLENGE_LEN;
    }
}

int ccsds_sdls_ep_verify_command_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_ep_verify_command *command)
{
    struct ccsds_sdls_ep_pdu pdu;
    size_t key_count;
    size_t offset = 0u;
    int ret;

    __ASSERT(command != NULL, "SDLS EP verification command output is NULL");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }
    if (pdu.type != CCSDS_SDLS_EP_COMMAND ||
        pdu.service_group != CCSDS_SDLS_EP_KEY_MANAGEMENT ||
        pdu.procedure != CCSDS_SDLS_EP_KEY_VERIFICATION) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    if (pdu.data_len == 0u ||
        pdu.data_len % CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN != 0u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    key_count = pdu.data_len / CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN;
    if (key_count > CCSDS_SDLS_EP_MAX_RECIPIENTS) {
        return CCSDS_SDLS_ERR_CAPACITY;
    }
    for (size_t i = 0u; i < key_count; i++) {
        command->entries[i].key_id = sys_get_be16(pdu.data + offset);
        offset += 2u;
        memcpy(command->entries[i].challenge, pdu.data + offset,
               CCSDS_SDLS_EP_CHALLENGE_LEN);
        offset += CCSDS_SDLS_EP_CHALLENGE_LEN;
    }
    command->key_count = key_count;
    return 0;
}

void ccsds_sdls_ep_verify_reply_encode(
    const struct ccsds_sdls_ep_verify_reply *reply, uint8_t *out,
    size_t out_capacity)
{
    size_t data_len;
    size_t offset = CCSDS_SDLS_EP_HEADER_LEN;

    __ASSERT(reply != NULL, "SDLS EP verification reply is NULL");
    __ASSERT(out != NULL, "SDLS EP verification reply output is NULL");
    __ASSERT(reply->key_count > 0u &&
                 reply->key_count <= CCSDS_SDLS_EP_MAX_RECIPIENTS,
             "invalid SDLS EP verification reply count");
    data_len = reply->key_count * CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN;
    __ASSERT(out_capacity >= pdu_size(data_len),
             "SDLS EP verification reply output is too small");

    encode_header(CCSDS_SDLS_EP_REPLY, CCSDS_SDLS_EP_KEY_MANAGEMENT,
                  CCSDS_SDLS_EP_KEY_VERIFICATION, data_len, out);
    for (size_t i = 0u; i < reply->key_count; i++) {
        sys_put_be16(reply->entries[i].key_id, out + offset);
        offset += 2u;
        memcpy(out + offset, reply->entries[i].iv, CCSDS_SDLS_IV_LEN);
        offset += CCSDS_SDLS_IV_LEN;
        memcpy(out + offset, reply->entries[i].encrypted_challenge,
               CCSDS_SDLS_EP_CHALLENGE_LEN);
        offset += CCSDS_SDLS_EP_CHALLENGE_LEN;
        memcpy(out + offset, reply->entries[i].tag, CCSDS_SDLS_TAG_LEN);
        offset += CCSDS_SDLS_TAG_LEN;
    }
}

int ccsds_sdls_ep_verify_reply_decode(const uint8_t *encoded,
                                      size_t encoded_len,
                                      struct ccsds_sdls_ep_verify_reply *reply)
{
    struct ccsds_sdls_ep_pdu pdu;
    size_t key_count;
    size_t offset = 0u;
    int ret;

    __ASSERT(reply != NULL, "SDLS EP verification reply output is NULL");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }
    if (pdu.type != CCSDS_SDLS_EP_REPLY ||
        pdu.service_group != CCSDS_SDLS_EP_KEY_MANAGEMENT ||
        pdu.procedure != CCSDS_SDLS_EP_KEY_VERIFICATION) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    if (pdu.data_len == 0u ||
        pdu.data_len % CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN != 0u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    key_count = pdu.data_len / CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN;
    if (key_count > CCSDS_SDLS_EP_MAX_RECIPIENTS) {
        return CCSDS_SDLS_ERR_CAPACITY;
    }
    for (size_t i = 0u; i < key_count; i++) {
        reply->entries[i].key_id = sys_get_be16(pdu.data + offset);
        offset += 2u;
        memcpy(reply->entries[i].iv, pdu.data + offset, CCSDS_SDLS_IV_LEN);
        offset += CCSDS_SDLS_IV_LEN;
        memcpy(reply->entries[i].encrypted_challenge, pdu.data + offset,
               CCSDS_SDLS_EP_CHALLENGE_LEN);
        offset += CCSDS_SDLS_EP_CHALLENGE_LEN;
        memcpy(reply->entries[i].tag, pdu.data + offset, CCSDS_SDLS_TAG_LEN);
        offset += CCSDS_SDLS_TAG_LEN;
    }
    reply->key_count = key_count;
    return 0;
}

static int decode_sa_pdu(const uint8_t *encoded, size_t encoded_len,
                         uint8_t type, uint8_t procedure, size_t data_len,
                         struct ccsds_sdls_ep_pdu *pdu)
{
    int ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, pdu);

    if (ret != 0) {
        return ret;
    }
    if (pdu->type != type ||
        pdu->service_group != CCSDS_SDLS_EP_SA_MANAGEMENT ||
        pdu->procedure != procedure) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    return pdu->data_len == data_len ? 0 : CCSDS_SDLS_ERR_FORMAT;
}

void ccsds_sdls_ep_start_sa_encode(const struct ccsds_sdls_ep_start_sa *command,
                                   uint8_t *out, size_t out_capacity)
{
    size_t data_len;

    __ASSERT(command != NULL, "SDLS EP Start SA command is NULL");
    __ASSERT(out != NULL, "SDLS EP Start SA output is NULL");
    __ASSERT(command->association_count <= CCSDS_SDLS_EP_MAX_ASSOCIATIONS,
             "too many SDLS EP Start SA associations");
    data_len = 2u + 4u * command->association_count;
    __ASSERT(out_capacity >= pdu_size(data_len),
             "SDLS EP Start SA output is too small");

    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_SA_MANAGEMENT,
                  CCSDS_SDLS_EP_START_SA, data_len, out);
    sys_put_be16(command->spi, out + CCSDS_SDLS_EP_HEADER_LEN);
    for (size_t i = 0u; i < command->association_count; i++) {
        sys_put_be32(command->associations[i],
                     out + CCSDS_SDLS_EP_HEADER_LEN + 2u + i * 4u);
    }
}

int ccsds_sdls_ep_start_sa_decode(const uint8_t *encoded, size_t encoded_len,
                                  struct ccsds_sdls_ep_start_sa *command)
{
    struct ccsds_sdls_ep_pdu pdu;
    size_t count;
    int ret;

    __ASSERT(command != NULL, "SDLS EP Start SA output is NULL");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }
    if (pdu.type != CCSDS_SDLS_EP_COMMAND ||
        pdu.service_group != CCSDS_SDLS_EP_SA_MANAGEMENT ||
        pdu.procedure != CCSDS_SDLS_EP_START_SA) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    if (pdu.data_len < 2u || (pdu.data_len - 2u) % 4u != 0u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    count = (pdu.data_len - 2u) / 4u;
    if (count > CCSDS_SDLS_EP_MAX_ASSOCIATIONS) {
        return CCSDS_SDLS_ERR_CAPACITY;
    }
    command->spi = sys_get_be16(pdu.data);
    for (size_t i = 0u; i < count; i++) {
        command->associations[i] = sys_get_be32(pdu.data + 2u + i * 4u);
    }
    command->association_count = count;
    return 0;
}

void ccsds_sdls_ep_sa_command_encode(
    enum ccsds_sdls_ep_sa_procedure procedure,
    const struct ccsds_sdls_ep_sa_command *command, uint8_t *out,
    size_t out_capacity)
{
    __ASSERT(procedure == CCSDS_SDLS_EP_STOP_SA ||
                 procedure == CCSDS_SDLS_EP_EXPIRE_SA ||
                 procedure == CCSDS_SDLS_EP_READ_ARSN ||
                 procedure == CCSDS_SDLS_EP_SA_STATUS,
             "invalid simple SDLS EP SA procedure");
    __ASSERT(command != NULL, "SDLS EP SA command is NULL");
    __ASSERT(out != NULL, "SDLS EP SA command output is NULL");
    __ASSERT(out_capacity >= pdu_size(2u),
             "SDLS EP SA command output is too small");
    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_SA_MANAGEMENT, procedure,
                  2u, out);
    sys_put_be16(command->spi, out + CCSDS_SDLS_EP_HEADER_LEN);
}

int ccsds_sdls_ep_sa_command_decode(
    const uint8_t *encoded, size_t encoded_len,
    enum ccsds_sdls_ep_sa_procedure expected_procedure,
    struct ccsds_sdls_ep_sa_command *command)
{
    struct ccsds_sdls_ep_pdu pdu;
    int ret;

    __ASSERT(command != NULL, "SDLS EP SA command output is NULL");
    ret = decode_sa_pdu(encoded, encoded_len, CCSDS_SDLS_EP_COMMAND,
                        expected_procedure, 2u, &pdu);
    if (ret == 0) {
        command->spi = sys_get_be16(pdu.data);
    }
    return ret;
}

void ccsds_sdls_ep_rekey_sa_encode(const struct ccsds_sdls_ep_rekey_sa *command,
                                   uint8_t *out, size_t out_capacity)
{
    size_t data_len;

    __ASSERT(command != NULL, "SDLS EP Rekey SA command is NULL");
    __ASSERT(out != NULL, "SDLS EP Rekey SA output is NULL");
    data_len = command->has_rx_arsn ? 8u : 4u;
    __ASSERT(out_capacity >= pdu_size(data_len),
             "SDLS EP Rekey SA output is too small");
    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_SA_MANAGEMENT,
                  CCSDS_SDLS_EP_REKEY_SA, data_len, out);
    sys_put_be16(command->spi, out + CCSDS_SDLS_EP_HEADER_LEN);
    sys_put_be16(command->key_id, out + CCSDS_SDLS_EP_HEADER_LEN + 2u);
    if (command->has_rx_arsn) {
        sys_put_be32(command->rx_arsn, out + CCSDS_SDLS_EP_HEADER_LEN + 4u);
    }
}

int ccsds_sdls_ep_rekey_sa_decode(const uint8_t *encoded, size_t encoded_len,
                                  struct ccsds_sdls_ep_rekey_sa *command)
{
    struct ccsds_sdls_ep_pdu pdu;
    int ret;

    __ASSERT(command != NULL, "SDLS EP Rekey SA output is NULL");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }
    if (pdu.type != CCSDS_SDLS_EP_COMMAND ||
        pdu.service_group != CCSDS_SDLS_EP_SA_MANAGEMENT ||
        pdu.procedure != CCSDS_SDLS_EP_REKEY_SA) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    if (pdu.data_len != 4u && pdu.data_len != 8u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    command->spi = sys_get_be16(pdu.data);
    command->key_id = sys_get_be16(pdu.data + 2u);
    command->has_rx_arsn = pdu.data_len == 8u;
    command->rx_arsn = command->has_rx_arsn ? sys_get_be32(pdu.data + 4u) : 0u;
    return 0;
}

static void set_u32_encode(uint8_t procedure, uint16_t spi, uint32_t value,
                           uint8_t *out, size_t out_capacity)
{
    __ASSERT(out != NULL, "SDLS EP integer output is NULL");
    __ASSERT(out_capacity >= pdu_size(6u),
             "SDLS EP integer output is too small");
    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_SA_MANAGEMENT, procedure,
                  6u, out);
    sys_put_be16(spi, out + CCSDS_SDLS_EP_HEADER_LEN);
    sys_put_be32(value, out + CCSDS_SDLS_EP_HEADER_LEN + 2u);
}

void ccsds_sdls_ep_set_arsn_encode(const struct ccsds_sdls_ep_set_arsn *command,
                                   uint8_t *out, size_t out_capacity)
{
    __ASSERT(command != NULL, "SDLS EP Set ARSN command is NULL");
    set_u32_encode(CCSDS_SDLS_EP_SET_ARSN, command->spi, command->arsn, out,
                   out_capacity);
}

int ccsds_sdls_ep_set_arsn_decode(const uint8_t *encoded, size_t encoded_len,
                                  struct ccsds_sdls_ep_set_arsn *command)
{
    struct ccsds_sdls_ep_pdu pdu;
    int ret;

    __ASSERT(command != NULL, "SDLS EP Set ARSN output is NULL");
    ret = decode_sa_pdu(encoded, encoded_len, CCSDS_SDLS_EP_COMMAND,
                        CCSDS_SDLS_EP_SET_ARSN, 6u, &pdu);
    if (ret == 0) {
        command->spi = sys_get_be16(pdu.data);
        command->arsn = sys_get_be32(pdu.data + 2u);
    }
    return ret;
}

void ccsds_sdls_ep_set_arsn_window_encode(
    const struct ccsds_sdls_ep_set_arsn_window *command, uint8_t *out,
    size_t out_capacity)
{
    __ASSERT(command != NULL, "SDLS EP Set ARSN window command is NULL");
    set_u32_encode(CCSDS_SDLS_EP_SET_ARSN_WINDOW, command->spi, command->window,
                   out, out_capacity);
}

int ccsds_sdls_ep_set_arsn_window_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_ep_set_arsn_window *command)
{
    struct ccsds_sdls_ep_pdu pdu;
    int ret;

    __ASSERT(command != NULL, "SDLS EP Set ARSN window output is NULL");
    ret = decode_sa_pdu(encoded, encoded_len, CCSDS_SDLS_EP_COMMAND,
                        CCSDS_SDLS_EP_SET_ARSN_WINDOW, 6u, &pdu);
    if (ret == 0) {
        command->spi = sys_get_be16(pdu.data);
        command->window = sys_get_be32(pdu.data + 2u);
    }
    return ret;
}

void ccsds_sdls_ep_read_arsn_reply_encode(
    const struct ccsds_sdls_ep_read_arsn_reply *reply, uint8_t *out,
    size_t out_capacity)
{
    __ASSERT(reply != NULL, "SDLS EP Read ARSN reply is NULL");
    __ASSERT(out != NULL, "SDLS EP Read ARSN reply output is NULL");
    __ASSERT(out_capacity >= pdu_size(6u),
             "SDLS EP Read ARSN reply output is too small");
    encode_header(CCSDS_SDLS_EP_REPLY, CCSDS_SDLS_EP_SA_MANAGEMENT,
                  CCSDS_SDLS_EP_READ_ARSN, 6u, out);
    sys_put_be16(reply->spi, out + CCSDS_SDLS_EP_HEADER_LEN);
    sys_put_be32(reply->arsn, out + CCSDS_SDLS_EP_HEADER_LEN + 2u);
}

int ccsds_sdls_ep_read_arsn_reply_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_ep_read_arsn_reply *reply)
{
    struct ccsds_sdls_ep_pdu pdu;
    int ret;

    __ASSERT(reply != NULL, "SDLS EP Read ARSN reply output is NULL");
    ret = decode_sa_pdu(encoded, encoded_len, CCSDS_SDLS_EP_REPLY,
                        CCSDS_SDLS_EP_READ_ARSN, 6u, &pdu);
    if (ret == 0) {
        reply->spi = sys_get_be16(pdu.data);
        reply->arsn = sys_get_be32(pdu.data + 2u);
    }
    return ret;
}

void ccsds_sdls_ep_sa_status_reply_encode(
    const struct ccsds_sdls_ep_sa_status_reply *reply, uint8_t *out,
    size_t out_capacity)
{
    __ASSERT(reply != NULL, "SDLS EP SA Status reply is NULL");
    __ASSERT(out != NULL, "SDLS EP SA Status reply output is NULL");
    __ASSERT(out_capacity >= pdu_size(3u),
             "SDLS EP SA Status reply output is too small");
    encode_header(CCSDS_SDLS_EP_REPLY, CCSDS_SDLS_EP_SA_MANAGEMENT,
                  CCSDS_SDLS_EP_SA_STATUS, 3u, out);
    sys_put_be16(reply->spi, out + CCSDS_SDLS_EP_HEADER_LEN);
    out[CCSDS_SDLS_EP_HEADER_LEN + 2u] = reply->last_procedure;
}

int ccsds_sdls_ep_sa_status_reply_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_ep_sa_status_reply *reply)
{
    struct ccsds_sdls_ep_pdu pdu;
    int ret;

    __ASSERT(reply != NULL, "SDLS EP SA Status reply output is NULL");
    ret = decode_sa_pdu(encoded, encoded_len, CCSDS_SDLS_EP_REPLY,
                        CCSDS_SDLS_EP_SA_STATUS, 3u, &pdu);
    if (ret == 0) {
        reply->spi = sys_get_be16(pdu.data);
        reply->last_procedure = pdu.data[2];
    }
    return ret;
}

void ccsds_sdls_ep_alarm_flag_reset_encode(uint8_t *out, size_t out_capacity)
{
    __ASSERT(out != NULL, "SDLS EP Alarm Flag Reset output is NULL");
    __ASSERT(out_capacity >= CCSDS_SDLS_EP_HEADER_LEN,
             "SDLS EP Alarm Flag Reset output is too small");
    encode_header(CCSDS_SDLS_EP_COMMAND, CCSDS_SDLS_EP_SECURITY_MONITORING,
                  CCSDS_SDLS_EP_ALARM_FLAG_RESET, 0u, out);
}

static int validate_key(psa_key_id_t key_id, psa_key_usage_t required_usage)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status = psa_get_key_attributes(key_id, &attributes);
    int ret = 0;

    if (status != PSA_SUCCESS) {
        return CCSDS_SDLS_ERR_PSA;
    }
    if (psa_get_key_type(&attributes) != PSA_KEY_TYPE_AES ||
        psa_get_key_bits(&attributes) != CCSDS_SDLS_AES_KEY_BITS ||
        psa_get_key_algorithm(&attributes) != PSA_ALG_GCM ||
        (psa_get_key_usage_flags(&attributes) & required_usage) !=
            required_usage) {
        ret = CCSDS_SDLS_ERR_KEY;
    }
    psa_reset_key_attributes(&attributes);
    return ret;
}

__weak psa_status_t ccsds_sdls_ep_psa_import_key(
    const psa_key_attributes_t *attributes, const uint8_t *data,
    size_t data_len, psa_key_id_t *key_id)
{
    return psa_import_key(attributes, data, data_len, key_id);
}

__weak psa_status_t ccsds_sdls_ep_psa_destroy_key(psa_key_id_t key_id)
{
    return psa_destroy_key(key_id);
}

int ccsds_sdls_ep_process_otar(struct ccsds_sdls_ctx *ctx,
                               const uint8_t *encoded, size_t encoded_len,
                               struct ccsds_sdls_workspace workspace)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t imported[CCSDS_SDLS_EP_MAX_OTAR_KEYS] = {0};
    uint16_t destinations[CCSDS_SDLS_EP_MAX_OTAR_KEYS] = {0};
    struct ccsds_sdls_ep_otar otar;
    struct ccsds_sdls_key *master;
    size_t plaintext_len;
    size_t output_len = 0u;
    size_t imported_count = 0u;
    bool seen[CONFIG_CCSDS_SDLS_MAX_KEYS] = {0};
    int ret;
    psa_status_t status;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP OTAR input is NULL");
    __ASSERT(workspace.data != NULL, "SDLS EP OTAR workspace is NULL");
    __ASSERT(workspace.capacity >= CCSDS_SDLS_EP_PLAINTEXT_MAX,
             "SDLS EP OTAR workspace is too small");

    ret = ccsds_sdls_ep_otar_decode(encoded, encoded_len, &otar);
    if (ret != 0) {
        goto out;
    }
    if (otar.master_key_id >= CONFIG_CCSDS_SDLS_SESSION_KEY_BASE ||
        ccsds_sdls_key_lookup(ctx, otar.master_key_id, &master) != 0 ||
        master->state != CCSDS_SDLS_KEY_ACTIVE) {
        ret = CCSDS_SDLS_ERR_KEY;
        goto out;
    }
    ret = validate_key(master->psa_key_id, PSA_KEY_USAGE_DECRYPT);
    if (ret != 0) {
        goto out;
    }

    plaintext_len = otar.key_count * CCSDS_SDLS_EP_OTAR_BLOCK_LEN;
    status = psa_aead_decrypt(
        master->psa_key_id, PSA_ALG_GCM,
        encoded + CCSDS_SDLS_EP_HEADER_LEN + 2u, CCSDS_SDLS_IV_LEN, encoded,
        CCSDS_SDLS_EP_HEADER_LEN + 2u,
        encoded + CCSDS_SDLS_EP_HEADER_LEN + 2u + CCSDS_SDLS_IV_LEN,
        plaintext_len + CCSDS_SDLS_TAG_LEN, workspace.data, plaintext_len,
        &output_len);
    if (status != PSA_SUCCESS) {
        ret = status == PSA_ERROR_INVALID_SIGNATURE
                  ? CCSDS_SDLS_ERR_AUTHENTICATION
                  : CCSDS_SDLS_ERR_PSA;
        goto out;
    }
    if (output_len != plaintext_len) {
        ret = CCSDS_SDLS_ERR_PSA;
        goto out;
    }

    for (size_t i = 0u; i < otar.key_count; i++) {
        uint16_t key_id =
            sys_get_be16(workspace.data + i * CCSDS_SDLS_EP_OTAR_BLOCK_LEN);

        if (key_id < CONFIG_CCSDS_SDLS_SESSION_KEY_BASE ||
            key_id >= CONFIG_CCSDS_SDLS_MAX_KEYS) {
            ret = CCSDS_SDLS_ERR_KEY;
            goto out;
        }
        if (seen[key_id]) {
            ret = CCSDS_SDLS_ERR_FORMAT;
            goto out;
        }
        if (ctx->keys[key_id].psa_key_id != PSA_KEY_ID_NULL) {
            ret = CCSDS_SDLS_ERR_KEY_STATE;
            goto out;
        }
        seen[key_id] = true;
        destinations[i] = key_id;
    }

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, CCSDS_SDLS_AES_KEY_BITS);
    for (; imported_count < otar.key_count; imported_count++) {
        const uint8_t *key =
            workspace.data + imported_count * CCSDS_SDLS_EP_OTAR_BLOCK_LEN + 2u;

        status = ccsds_sdls_ep_psa_import_key(
            &attributes, key, CCSDS_SDLS_EP_KEY_LEN, &imported[imported_count]);
        if (status != PSA_SUCCESS) {
            ret = CCSDS_SDLS_ERR_PSA;
            goto out;
        }
    }

    for (size_t i = 0u; i < otar.key_count; i++) {
        struct ccsds_sdls_key *key = &ctx->keys[destinations[i]];

        key->psa_key_id = imported[i];
        key->state = CCSDS_SDLS_KEY_PREACTIVE;
        key->tx_arsn = 0u;
        imported[i] = PSA_KEY_ID_NULL;
    }
    ret = 0;

out:
    for (size_t i = 0u; i < imported_count; i++) {
        if (imported[i] != PSA_KEY_ID_NULL) {
            (void)ccsds_sdls_ep_psa_destroy_key(imported[i]);
        }
    }
    psa_reset_key_attributes(&attributes);
    wipe(&otar, sizeof(otar));
    wipe(imported, sizeof(imported));
    wipe(destinations, sizeof(destinations));
    wipe(seen, sizeof(seen));
    wipe(workspace.data, workspace.capacity);
    return ret;
}

static int process_lifecycle(struct ccsds_sdls_ctx *ctx, const uint8_t *encoded,
                             size_t encoded_len,
                             enum ccsds_sdls_ep_procedure procedure)
{
    struct ccsds_sdls_ep_key_command command;
    bool seen[CONFIG_CCSDS_SDLS_MAX_KEYS] = {0};
    uint8_t required_state = procedure == CCSDS_SDLS_EP_KEY_ACTIVATION
                                 ? CCSDS_SDLS_KEY_PREACTIVE
                                 : CCSDS_SDLS_KEY_ACTIVE;
    int ret;

    ret = ccsds_sdls_ep_key_command_decode(encoded, encoded_len, procedure,
                                           &command);
    if (ret != 0) {
        return ret;
    }
    for (size_t i = 0u; i < command.key_count; i++) {
        uint16_t key_id = command.key_ids[i];
        struct ccsds_sdls_key *key;

        if (key_id < CONFIG_CCSDS_SDLS_SESSION_KEY_BASE ||
            key_id >= CONFIG_CCSDS_SDLS_MAX_KEYS || seen[key_id] ||
            ccsds_sdls_key_lookup(ctx, key_id, &key) != 0) {
            return CCSDS_SDLS_ERR_KEY;
        }
        seen[key_id] = true;
        if (procedure == CCSDS_SDLS_EP_KEY_DEACTIVATION) {
            if (key->state != CCSDS_SDLS_KEY_ACTIVE &&
                key->state != CCSDS_SDLS_KEY_PREACTIVE) {
                return CCSDS_SDLS_ERR_KEY_STATE;
            }
        } else if (key->state != required_state) {
            return CCSDS_SDLS_ERR_KEY_STATE;
        }
        ret = validate_key(key->psa_key_id,
                           PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        if (ret != 0) {
            return ret;
        }
    }
    for (size_t i = 0u; i < command.key_count; i++) {
        ctx->keys[command.key_ids[i]].state =
            procedure == CCSDS_SDLS_EP_KEY_ACTIVATION
                ? CCSDS_SDLS_KEY_ACTIVE
                : CCSDS_SDLS_KEY_DEACTIVATED;
    }
    return 0;
}

int ccsds_sdls_ep_process_key_activation(struct ccsds_sdls_ctx *ctx,
                                         const uint8_t *encoded,
                                         size_t encoded_len)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP activation input is NULL");
    return process_lifecycle(ctx, encoded, encoded_len,
                             CCSDS_SDLS_EP_KEY_ACTIVATION);
}

int ccsds_sdls_ep_process_key_deactivation(struct ccsds_sdls_ctx *ctx,
                                           const uint8_t *encoded,
                                           size_t encoded_len)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP deactivation input is NULL");
    return process_lifecycle(ctx, encoded, encoded_len,
                             CCSDS_SDLS_EP_KEY_DEACTIVATION);
}

int ccsds_sdls_ep_process_key_verification(
    struct ccsds_sdls_ctx *ctx, const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_workspace workspace, uint8_t *reply,
    size_t reply_capacity)
{
    struct ccsds_sdls_ep_verify_command command;
    struct ccsds_sdls_ep_verify_reply response;
    bool seen[CONFIG_CCSDS_SDLS_MAX_KEYS] = {0};
    uint64_t next_iv;
    size_t reply_len;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP verification input is NULL");
    __ASSERT(reply != NULL, "SDLS EP verification output is NULL");
    __ASSERT(workspace.data != NULL, "SDLS EP verification workspace is NULL");
    __ASSERT(workspace.capacity >= CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX,
             "SDLS EP verification workspace is too small");

    ret = ccsds_sdls_ep_verify_command_decode(encoded, encoded_len, &command);
    if (ret != 0) {
        goto out;
    }
    reply_len = CCSDS_SDLS_EP_HEADER_LEN +
                command.key_count * CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN;
    __ASSERT(reply_capacity >= reply_len,
             "SDLS EP verification output is too small");
    response.key_count = command.key_count;
    for (size_t i = 0u; i < command.key_count; i++) {
        uint16_t key_id = command.entries[i].key_id;
        struct ccsds_sdls_key *key;

        if (key_id < CONFIG_CCSDS_SDLS_SESSION_KEY_BASE ||
            key_id >= CONFIG_CCSDS_SDLS_MAX_KEYS || seen[key_id] ||
            ccsds_sdls_key_lookup(ctx, key_id, &key) != 0) {
            ret = CCSDS_SDLS_ERR_KEY;
            goto out;
        }
        seen[key_id] = true;
        if (key->state == CCSDS_SDLS_KEY_DEACTIVATED) {
            ret = CCSDS_SDLS_ERR_KEY_STATE;
            goto out;
        }
        ret = validate_key(key->psa_key_id, PSA_KEY_USAGE_ENCRYPT);
        if (ret != 0) {
            goto out;
        }
    }

    next_iv = ctx->tx_iv;
    for (size_t i = 0u; i < command.key_count; i++) {
        struct ccsds_sdls_key *key = &ctx->keys[command.entries[i].key_id];
        struct ccsds_sdls_ep_verify_reply_entry *entry = &response.entries[i];
        size_t output_len = 0u;
        psa_status_t status;

        entry->key_id = command.entries[i].key_id;
        ccsds_sdls_construct_iv(next_iv, key->tx_arsn, entry->iv);
        next_iv += CCSDS_SDLS_IV_STRIDE;
        status = psa_aead_encrypt(
            key->psa_key_id, PSA_ALG_GCM, entry->iv, sizeof(entry->iv), NULL,
            0u, command.entries[i].challenge, CCSDS_SDLS_EP_CHALLENGE_LEN,
            entry->encrypted_challenge,
            CCSDS_SDLS_EP_CHALLENGE_LEN + CCSDS_SDLS_TAG_LEN, &output_len);
        if (status != PSA_SUCCESS ||
            output_len != CCSDS_SDLS_EP_CHALLENGE_LEN + CCSDS_SDLS_TAG_LEN) {
            ret = CCSDS_SDLS_ERR_PSA;
            goto out;
        }
    }

    ccsds_sdls_ep_verify_reply_encode(&response, workspace.data,
                                      workspace.capacity);
    memmove(reply, workspace.data, reply_len);
    for (size_t i = 0u; i < command.key_count; i++) {
        ctx->keys[command.entries[i].key_id].tx_arsn++;
    }
    ctx->tx_iv = next_iv;
    ret = 0;

out:
    wipe(&command, sizeof(command));
    wipe(&response, sizeof(response));
    wipe(seen, sizeof(seen));
    wipe(workspace.data, workspace.capacity);
    return ret;
}

int ccsds_sdls_ep_check_key_verification(struct ccsds_sdls_ctx *ctx,
                                         const uint8_t *command_encoded,
                                         size_t command_len,
                                         const uint8_t *reply_encoded,
                                         size_t reply_len,
                                         struct ccsds_sdls_workspace workspace)
{
    struct ccsds_sdls_ep_verify_command command;
    struct ccsds_sdls_ep_verify_reply reply;
    bool seen[CONFIG_CCSDS_SDLS_MAX_KEYS] = {0};
    uint8_t clear[CCSDS_SDLS_EP_CHALLENGE_LEN];
    size_t clear_len;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(command_encoded != NULL,
             "SDLS EP verification command input is NULL");
    __ASSERT(reply_encoded != NULL, "SDLS EP verification reply input is NULL");
    __ASSERT(workspace.data != NULL,
             "SDLS EP verification check workspace is NULL");
    __ASSERT(workspace.capacity >= CCSDS_SDLS_EP_CHALLENGE_LEN,
             "SDLS EP verification check workspace is too small");

    ret = ccsds_sdls_ep_verify_command_decode(command_encoded, command_len,
                                              &command);
    if (ret != 0) {
        goto out;
    }
    ret = ccsds_sdls_ep_verify_reply_decode(reply_encoded, reply_len, &reply);
    if (ret != 0) {
        goto out;
    }
    if (reply.key_count != command.key_count) {
        ret = CCSDS_SDLS_ERR_FORMAT;
        goto out;
    }
    for (size_t i = 0u; i < command.key_count; i++) {
        struct ccsds_sdls_key *key;
        psa_status_t status;

        if (reply.entries[i].key_id != command.entries[i].key_id ||
            reply.entries[i].key_id < CONFIG_CCSDS_SDLS_SESSION_KEY_BASE ||
            reply.entries[i].key_id >= CONFIG_CCSDS_SDLS_MAX_KEYS ||
            seen[reply.entries[i].key_id] ||
            ccsds_sdls_key_lookup(ctx, reply.entries[i].key_id, &key) != 0) {
            ret = CCSDS_SDLS_ERR_KEY;
            goto out;
        }
        seen[reply.entries[i].key_id] = true;
        ret = validate_key(key->psa_key_id, PSA_KEY_USAGE_DECRYPT);
        if (ret != 0) {
            goto out;
        }
        status = psa_aead_decrypt(
            key->psa_key_id, PSA_ALG_GCM, reply.entries[i].iv,
            CCSDS_SDLS_IV_LEN, NULL, 0u, reply.entries[i].encrypted_challenge,
            CCSDS_SDLS_EP_CHALLENGE_LEN + CCSDS_SDLS_TAG_LEN, clear,
            sizeof(clear), &clear_len);
        if (status != PSA_SUCCESS) {
            ret = status == PSA_ERROR_INVALID_SIGNATURE
                      ? CCSDS_SDLS_ERR_AUTHENTICATION
                      : CCSDS_SDLS_ERR_PSA;
            goto out;
        }
        if (clear_len != CCSDS_SDLS_EP_CHALLENGE_LEN ||
            memcmp(clear, command.entries[i].challenge,
                   CCSDS_SDLS_EP_CHALLENGE_LEN) != 0) {
            ret = CCSDS_SDLS_ERR_AUTHENTICATION;
            goto out;
        }
    }
    ret = 0;

out:
    wipe(&command, sizeof(command));
    wipe(&reply, sizeof(reply));
    wipe(clear, sizeof(clear));
    wipe(seen, sizeof(seen));
    wipe(workspace.data, workspace.capacity);
    return ret;
}

static bool sa_role_is_rx(uint8_t role)
{
    return role == CCSDS_SDLS_SA_EP_COMMAND_RX ||
           role == CCSDS_SDLS_SA_OPERATIONAL_TC_RX;
}

static bool sa_role_is_tx(uint8_t role)
{
    return role == CCSDS_SDLS_SA_EP_REPLY_TX ||
           role == CCSDS_SDLS_SA_OPERATIONAL_TM_TX;
}

static int managed_sa(struct ccsds_sdls_ctx *ctx, uint16_t spi,
                      struct ccsds_sdls_sa **sa, size_t *slot)
{
    if (spi == 0u || spi == UINT16_MAX ||
        ccsds_sdls_sa_lookup(ctx, spi, sa) != 0) {
        return CCSDS_SDLS_ERR_UNKNOWN_SA;
    }
    *slot = spi - 1u;
    return 0;
}

static int validate_sa_key(struct ccsds_sdls_ctx *ctx, size_t slot,
                           uint16_t key_id)
{
    struct ccsds_sdls_key *key;
    bool tx = sa_role_is_tx(ctx->sa_roles[slot]);
    psa_key_usage_t usage = tx ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT;
    int ret;

    if (key_id < CONFIG_CCSDS_SDLS_SESSION_KEY_BASE ||
        key_id >= CONFIG_CCSDS_SDLS_MAX_KEYS ||
        ccsds_sdls_key_lookup(ctx, key_id, &key) != 0) {
        return CCSDS_SDLS_ERR_KEY;
    }
    if (key->state != CCSDS_SDLS_KEY_ACTIVE) {
        return CCSDS_SDLS_ERR_KEY_STATE;
    }
    ret = validate_key(key->psa_key_id, usage);
    if (ret != 0) {
        return ret;
    }

    for (size_t i = 0u; i < CONFIG_CCSDS_SDLS_MAX_SA; i++) {
        if (i == slot || !ctx->sas[i].configured ||
            ctx->sas[i].key_slot != key_id) {
            continue;
        }
        if (sa_role_is_tx(ctx->sa_roles[i]) != tx ||
            ctx->sa_modes[i] != ctx->sa_modes[slot]) {
            return CCSDS_SDLS_ERR_KEY;
        }
    }
    return 0;
}

int ccsds_sdls_ep_process_start_sa(struct ccsds_sdls_ctx *ctx,
                                   const uint8_t *encoded, size_t encoded_len)
{
    struct ccsds_sdls_ep_start_sa command;
    struct ccsds_sdls_sa *sa;
    size_t slot;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Start SA input is NULL");
    ret = ccsds_sdls_ep_start_sa_decode(encoded, encoded_len, &command);
    if (ret != 0) {
        return ret;
    }
    ret = managed_sa(ctx, command.spi, &sa, &slot);
    if (ret != 0) {
        return ret;
    }
    if (sa->state != CCSDS_SDLS_SA_STOPPED) {
        return CCSDS_SDLS_ERR_SA_STATE;
    }
    ret = validate_sa_key(ctx, slot, sa->key_slot);
    if (ret != 0) {
        return ret;
    }

    sa->state = CCSDS_SDLS_SA_OPERATIONAL;
    sa->last_procedure =
        (CCSDS_SDLS_EP_SA_MANAGEMENT << 4) | CCSDS_SDLS_EP_START_SA;
    return 0;
}

static int process_sa_transition(struct ccsds_sdls_ctx *ctx,
                                 const uint8_t *encoded, size_t encoded_len,
                                 enum ccsds_sdls_ep_sa_procedure procedure,
                                 enum ccsds_sdls_sa_state from,
                                 enum ccsds_sdls_sa_state to)
{
    struct ccsds_sdls_ep_sa_command command;
    struct ccsds_sdls_sa *sa;
    size_t slot;
    int ret;

    ret = ccsds_sdls_ep_sa_command_decode(encoded, encoded_len, procedure,
                                          &command);
    if (ret != 0) {
        return ret;
    }
    ret = managed_sa(ctx, command.spi, &sa, &slot);
    if (ret != 0) {
        return ret;
    }
    ARG_UNUSED(slot);
    if (sa->state != from) {
        return CCSDS_SDLS_ERR_SA_STATE;
    }
    sa->state = to;
    sa->last_procedure = (CCSDS_SDLS_EP_SA_MANAGEMENT << 4) | procedure;
    return 0;
}

int ccsds_sdls_ep_process_stop_sa(struct ccsds_sdls_ctx *ctx,
                                  const uint8_t *encoded, size_t encoded_len)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Stop SA input is NULL");
    return process_sa_transition(
        ctx, encoded, encoded_len, CCSDS_SDLS_EP_STOP_SA,
        CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_SA_STOPPED);
}

int ccsds_sdls_ep_process_expire_sa(struct ccsds_sdls_ctx *ctx,
                                    const uint8_t *encoded, size_t encoded_len)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Expire SA input is NULL");
    return process_sa_transition(ctx, encoded, encoded_len,
                                 CCSDS_SDLS_EP_EXPIRE_SA, CCSDS_SDLS_SA_STOPPED,
                                 CCSDS_SDLS_SA_EXPIRED);
}

int ccsds_sdls_ep_process_rekey_sa(struct ccsds_sdls_ctx *ctx,
                                   const uint8_t *encoded, size_t encoded_len)
{
    struct ccsds_sdls_ep_rekey_sa command;
    struct ccsds_sdls_sa *sa;
    size_t slot;
    bool rx;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Rekey SA input is NULL");
    ret = ccsds_sdls_ep_rekey_sa_decode(encoded, encoded_len, &command);
    if (ret != 0) {
        return ret;
    }
    ret = managed_sa(ctx, command.spi, &sa, &slot);
    if (ret != 0) {
        return ret;
    }
    if (sa->state != CCSDS_SDLS_SA_EXPIRED) {
        return CCSDS_SDLS_ERR_SA_STATE;
    }
    rx = sa_role_is_rx(ctx->sa_roles[slot]);
    if (rx == !command.has_rx_arsn) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    ret = validate_sa_key(ctx, slot, command.key_id);
    if (ret != 0) {
        return ret;
    }

    sa->key_slot = (uint8_t)command.key_id;
    if (rx) {
        sa->rx_arsn = command.rx_arsn;
        sa->rx_arsn_initialized = true;
    }
    sa->state = CCSDS_SDLS_SA_STOPPED;
    sa->last_procedure =
        (CCSDS_SDLS_EP_SA_MANAGEMENT << 4) | CCSDS_SDLS_EP_REKEY_SA;
    return 0;
}

static int mutable_rx_sa(struct ccsds_sdls_ctx *ctx, uint16_t spi,
                         struct ccsds_sdls_sa **sa, size_t *slot)
{
    int ret = managed_sa(ctx, spi, sa, slot);

    if (ret != 0) {
        return ret;
    }
    if (!sa_role_is_rx(ctx->sa_roles[*slot])) {
        return CCSDS_SDLS_ERR_SA_STATE;
    }
    if ((*sa)->state == CCSDS_SDLS_SA_EXPIRED) {
        return CCSDS_SDLS_ERR_SA_STATE;
    }
    return 0;
}

int ccsds_sdls_ep_process_set_arsn(struct ccsds_sdls_ctx *ctx,
                                   const uint8_t *encoded, size_t encoded_len)
{
    struct ccsds_sdls_ep_set_arsn command;
    struct ccsds_sdls_sa *sa;
    size_t slot;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Set ARSN input is NULL");
    ret = ccsds_sdls_ep_set_arsn_decode(encoded, encoded_len, &command);
    if (ret != 0) {
        return ret;
    }
    ret = mutable_rx_sa(ctx, command.spi, &sa, &slot);
    if (ret != 0) {
        return ret;
    }
    ARG_UNUSED(slot);
    if (sa->rx_arsn_initialized && command.arsn < sa->rx_arsn) {
        return CCSDS_SDLS_ERR_REPLAY;
    }
    sa->rx_arsn = command.arsn;
    sa->rx_arsn_initialized = true;
    sa->last_procedure =
        (CCSDS_SDLS_EP_SA_MANAGEMENT << 4) | CCSDS_SDLS_EP_SET_ARSN;
    return 0;
}

int ccsds_sdls_ep_process_set_arsn_window(struct ccsds_sdls_ctx *ctx,
                                          const uint8_t *encoded,
                                          size_t encoded_len)
{
    struct ccsds_sdls_ep_set_arsn_window command;
    struct ccsds_sdls_sa *sa;
    size_t slot;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Set ARSN window input is NULL");
    ret = ccsds_sdls_ep_set_arsn_window_decode(encoded, encoded_len, &command);
    if (ret != 0) {
        return ret;
    }
    if (command.window == 0u ||
        command.window > CONFIG_CCSDS_SDLS_ARSN_WINDOW) {
        return CCSDS_SDLS_ERR_CAPACITY;
    }
    ret = mutable_rx_sa(ctx, command.spi, &sa, &slot);
    if (ret != 0) {
        return ret;
    }
    ARG_UNUSED(slot);
    sa->rx_window = command.window;
    sa->last_procedure =
        (CCSDS_SDLS_EP_SA_MANAGEMENT << 4) | CCSDS_SDLS_EP_SET_ARSN_WINDOW;
    return 0;
}

int ccsds_sdls_ep_process_read_arsn(struct ccsds_sdls_ctx *ctx,
                                    const uint8_t *encoded, size_t encoded_len,
                                    uint8_t *reply, size_t reply_capacity,
                                    size_t *reply_len)
{
    struct ccsds_sdls_ep_read_arsn_reply response;
    struct ccsds_sdls_ep_sa_command command;
    struct ccsds_sdls_sa *sa;
    uint8_t encoded_reply[CCSDS_SDLS_EP_SA_REPLY_PDU_MAX];
    size_t slot;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Read ARSN input is NULL");
    __ASSERT(reply != NULL, "SDLS EP Read ARSN reply is NULL");
    __ASSERT(reply_len != NULL, "SDLS EP Read ARSN reply length is NULL");
    __ASSERT(reply_capacity >= sizeof(encoded_reply),
             "SDLS EP Read ARSN reply is too small");
    ret = ccsds_sdls_ep_sa_command_decode(encoded, encoded_len,
                                          CCSDS_SDLS_EP_READ_ARSN, &command);
    if (ret != 0) {
        return ret;
    }
    ret = mutable_rx_sa(ctx, command.spi, &sa, &slot);
    if (ret != 0) {
        return ret;
    }
    ARG_UNUSED(slot);
    response.spi = command.spi;
    response.arsn = sa->rx_arsn;
    ccsds_sdls_ep_read_arsn_reply_encode(&response, encoded_reply,
                                         sizeof(encoded_reply));
    memcpy(reply, encoded_reply, sizeof(encoded_reply));
    *reply_len = sizeof(encoded_reply);
    return 0;
}

int ccsds_sdls_ep_process_sa_status(struct ccsds_sdls_ctx *ctx,
                                    const uint8_t *encoded, size_t encoded_len,
                                    uint8_t *reply, size_t reply_capacity,
                                    size_t *reply_len)
{
    struct ccsds_sdls_ep_sa_status_reply response;
    struct ccsds_sdls_ep_sa_command command;
    struct ccsds_sdls_sa *sa;
    uint8_t encoded_reply[CCSDS_SDLS_EP_HEADER_LEN + 3u];
    size_t slot;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP SA Status input is NULL");
    __ASSERT(reply != NULL, "SDLS EP SA Status reply is NULL");
    __ASSERT(reply_len != NULL, "SDLS EP SA Status reply length is NULL");
    __ASSERT(reply_capacity >= sizeof(encoded_reply),
             "SDLS EP SA Status reply is too small");
    ret = ccsds_sdls_ep_sa_command_decode(encoded, encoded_len,
                                          CCSDS_SDLS_EP_SA_STATUS, &command);
    if (ret != 0) {
        return ret;
    }
    ret = managed_sa(ctx, command.spi, &sa, &slot);
    if (ret != 0) {
        return ret;
    }
    ARG_UNUSED(slot);
    response.spi = command.spi;
    response.last_procedure = sa->last_procedure;
    ccsds_sdls_ep_sa_status_reply_encode(&response, encoded_reply,
                                         sizeof(encoded_reply));
    memcpy(reply, encoded_reply, sizeof(encoded_reply));
    *reply_len = sizeof(encoded_reply);
    return 0;
}

int ccsds_sdls_ep_process_alarm_flag_reset(struct ccsds_sdls_ctx *ctx,
                                           const uint8_t *encoded,
                                           size_t encoded_len)
{
    struct ccsds_sdls_ep_pdu pdu;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP Alarm Flag Reset input is NULL");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }
    if (pdu.type != CCSDS_SDLS_EP_COMMAND ||
        pdu.service_group != CCSDS_SDLS_EP_SECURITY_MONITORING ||
        pdu.procedure != CCSDS_SDLS_EP_ALARM_FLAG_RESET) {
        return CCSDS_SDLS_ERR_UNSUPPORTED;
    }
    if (pdu.data_len != 0u) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    ctx->fsr.alarm = false;
    ctx->fsr.bad_sequence = false;
    ctx->fsr.bad_mac = false;
    ctx->fsr.bad_sa = false;
    return 0;
}

int ccsds_sdls_ep_process_pdu(
    struct ccsds_sdls_ctx *ctx, const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_workspace workspace, uint8_t *reply,
    size_t reply_capacity, size_t *reply_len)
{
    struct ccsds_sdls_ep_pdu pdu;
    size_t committed_reply_len = 0u;
    int ret;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(encoded != NULL, "SDLS EP packet payload is NULL");
    __ASSERT(reply_len != NULL, "SDLS EP reply length is NULL");
    ret = ccsds_sdls_ep_pdu_decode(encoded, encoded_len, &pdu);
    if (ret != 0) {
        return ret;
    }

    if (pdu.service_group == CCSDS_SDLS_EP_SA_MANAGEMENT &&
        pdu.type == CCSDS_SDLS_EP_COMMAND && pdu.data_len >= 2u &&
        pdu.procedure != CCSDS_SDLS_EP_READ_ARSN &&
        pdu.procedure != CCSDS_SDLS_EP_SA_STATUS &&
        ctx->authenticated_rx_valid &&
        sys_get_be16(pdu.data) == ctx->authenticated_rx_spi) {
        return CCSDS_SDLS_ERR_SA_STATE;
    }

    if (pdu.service_group == CCSDS_SDLS_EP_KEY_MANAGEMENT) {
        switch (pdu.procedure) {
        case CCSDS_SDLS_EP_OTAR:
            ret = ccsds_sdls_ep_process_otar(ctx, encoded, encoded_len,
                                             workspace);
            break;
        case CCSDS_SDLS_EP_KEY_ACTIVATION:
            ret =
                ccsds_sdls_ep_process_key_activation(ctx, encoded, encoded_len);
            break;
        case CCSDS_SDLS_EP_KEY_DEACTIVATION:
            ret = ccsds_sdls_ep_process_key_deactivation(ctx, encoded,
                                                         encoded_len);
            break;
        case CCSDS_SDLS_EP_KEY_VERIFICATION:
            __ASSERT(reply != NULL, "SDLS EP verification reply is NULL");
            ret = ccsds_sdls_ep_process_key_verification(
                ctx, encoded, encoded_len, workspace, reply, reply_capacity);
            if (ret == 0) {
                committed_reply_len =
                    CCSDS_SDLS_EP_HEADER_LEN +
                    (pdu.data_len / CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN) *
                        CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN;
            }
            break;
        default:
            ret = CCSDS_SDLS_ERR_UNSUPPORTED;
            break;
        }
    } else if (pdu.service_group == CCSDS_SDLS_EP_SA_MANAGEMENT) {
        switch (pdu.procedure) {
        case CCSDS_SDLS_EP_START_SA:
            ret = ccsds_sdls_ep_process_start_sa(ctx, encoded, encoded_len);
            break;
        case CCSDS_SDLS_EP_STOP_SA:
            ret = ccsds_sdls_ep_process_stop_sa(ctx, encoded, encoded_len);
            break;
        case CCSDS_SDLS_EP_REKEY_SA:
            ret = ccsds_sdls_ep_process_rekey_sa(ctx, encoded, encoded_len);
            break;
        case CCSDS_SDLS_EP_EXPIRE_SA:
            ret = ccsds_sdls_ep_process_expire_sa(ctx, encoded, encoded_len);
            break;
        case CCSDS_SDLS_EP_SET_ARSN:
            ret = ccsds_sdls_ep_process_set_arsn(ctx, encoded, encoded_len);
            break;
        case CCSDS_SDLS_EP_SET_ARSN_WINDOW:
            ret = ccsds_sdls_ep_process_set_arsn_window(ctx, encoded,
                                                        encoded_len);
            break;
        case CCSDS_SDLS_EP_READ_ARSN:
            __ASSERT(reply != NULL, "SDLS EP Read ARSN reply is NULL");
            ret = ccsds_sdls_ep_process_read_arsn(ctx, encoded, encoded_len,
                                                  reply, reply_capacity,
                                                  &committed_reply_len);
            break;
        case CCSDS_SDLS_EP_SA_STATUS:
            __ASSERT(reply != NULL, "SDLS EP SA Status reply is NULL");
            ret = ccsds_sdls_ep_process_sa_status(ctx, encoded, encoded_len,
                                                  reply, reply_capacity,
                                                  &committed_reply_len);
            break;
        default:
            ret = CCSDS_SDLS_ERR_UNSUPPORTED;
            break;
        }
    } else if (pdu.service_group == CCSDS_SDLS_EP_SECURITY_MONITORING &&
               pdu.procedure == CCSDS_SDLS_EP_ALARM_FLAG_RESET) {
        ret = ccsds_sdls_ep_process_alarm_flag_reset(ctx, encoded, encoded_len);
    } else {
        ret = CCSDS_SDLS_ERR_UNSUPPORTED;
    }

    if (ret != 0) {
        return ret;
    }
    *reply_len = committed_reply_len;
    return 0;
}
