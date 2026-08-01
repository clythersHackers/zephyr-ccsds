#include "ccsds_sdls.h"

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <psa/crypto_values.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/byteorder.h>

const uint8_t
    ccsds_sdls_tm_default_auth_mask[CCSDS_SDLS_TM_DEFAULT_AUTH_MASK_LEN] = {
        0x3fu, 0xfeu, 0x00u, 0x00u, 0x00u, 0x00u};
const uint8_t
    ccsds_sdls_tc_default_auth_mask[CCSDS_SDLS_TC_DEFAULT_AUTH_MASK_LEN] = {
        0x03u, 0xffu, 0xfcu, 0x00u, 0x00u};

#define ASSERT_AUTH_CONTRACT(auth)                                             \
    do {                                                                       \
        __ASSERT((auth).data != NULL || (auth).len == 0u,                      \
                 "SDLS authentication header is NULL");                        \
        __ASSERT((auth).mask_len <= (auth).len,                                \
                 "SDLS authentication mask exceeds header");                   \
        __ASSERT((auth).mask != NULL || (auth).mask_len == 0u,                 \
                 "SDLS authentication mask is NULL");                          \
    } while (false)

void ccsds_sdls_init(struct ccsds_sdls_ctx *ctx,
                     const struct ccsds_sdls_sa_init *sas, size_t sa_count,
                     const struct ccsds_sdls_key_init *keys, size_t key_count)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(sas != NULL || sa_count == 0u, "SDLS SA configuration is NULL");
    __ASSERT(keys != NULL || key_count == 0u, "SDLS key configuration is NULL");
    __ASSERT(sa_count <= CONFIG_CCSDS_SDLS_MAX_SA, "too many SDLS SAs");
    __ASSERT(key_count <= CONFIG_CCSDS_SDLS_MAX_KEYS, "too many SDLS keys");

    memset(ctx, 0, sizeof(*ctx));
    ctx->tx_iv = CCSDS_SDLS_IV_SEED;

    for (size_t i = 0u; i < key_count; i++) {
        uint16_t key_id = keys[i].key_id;

        __ASSERT(keys[i].psa_key_id != PSA_KEY_ID_NULL,
                 "SDLS PSA key ID is null");
        __ASSERT(key_id < CONFIG_CCSDS_SDLS_MAX_KEYS,
                 "SDLS key ID is outside the configured range");
        __ASSERT(keys[i].state >= CCSDS_SDLS_KEY_PREACTIVE &&
                     keys[i].state <= CCSDS_SDLS_KEY_DEACTIVATED,
                 "invalid SDLS key state");
        __ASSERT(ctx->keys[key_id].psa_key_id == PSA_KEY_ID_NULL,
                 "duplicate SDLS key ID");

        ctx->keys[key_id].psa_key_id = keys[i].psa_key_id;
        ctx->keys[key_id].state = (uint8_t)keys[i].state;
    }

    for (size_t i = 0u; i < sa_count; i++) {
        bool rx_role = sas[i].role == CCSDS_SDLS_SA_EP_COMMAND_RX ||
                       sas[i].role == CCSDS_SDLS_SA_OPERATIONAL_TC_RX;
        bool tx_role = sas[i].role == CCSDS_SDLS_SA_EP_REPLY_TX ||
                       sas[i].role == CCSDS_SDLS_SA_OPERATIONAL_TM_TX;
        uint16_t spi = sas[i].spi;
        size_t sa_slot;

        __ASSERT(spi > 0u && spi <= CONFIG_CCSDS_SDLS_MAX_SA,
                 "SDLS SPI is outside the configured range");
        sa_slot = spi - 1u;
        __ASSERT(!ctx->sas[sa_slot].configured, "duplicate SDLS SPI");
        __ASSERT(rx_role || tx_role, "invalid SDLS SA role");
        __ASSERT(sas[i].mode == CCSDS_SDLS_MODE_GMAC ||
                     sas[i].mode == CCSDS_SDLS_MODE_GCM,
                 "invalid SDLS security mode");
        __ASSERT(sas[i].state >= CCSDS_SDLS_SA_STOPPED &&
                     sas[i].state <= CCSDS_SDLS_SA_EXPIRED,
                 "invalid SDLS SA state");
        __ASSERT(rx_role || !sas[i].rx_arsn_initialized,
                 "TX SA has receive ARSN state");
        __ASSERT(sas[i].rx_arsn_initialized || sas[i].rx_arsn == 0u,
                 "uninitialized receive ARSN is nonzero");
        if (sas[i].has_key) {
            __ASSERT(sas[i].key_id >= CONFIG_CCSDS_SDLS_SESSION_KEY_BASE &&
                         sas[i].key_id < CONFIG_CCSDS_SDLS_MAX_KEYS,
                     "SDLS SA must reference a session-key slot");
        }

        ctx->sa_roles[sa_slot] = (uint8_t)sas[i].role;
        ctx->sa_modes[sa_slot] = (uint8_t)sas[i].mode;
        ctx->sas[sa_slot].key_slot =
            sas[i].has_key ? (uint8_t)sas[i].key_id
                           : CCSDS_SDLS_KEY_SLOT_NONE;
        ctx->sas[sa_slot].state = (uint8_t)sas[i].state;
        ctx->sas[sa_slot].rx_arsn = sas[i].rx_arsn;
        ctx->sas[sa_slot].rx_arsn_initialized = sas[i].rx_arsn_initialized;
        ctx->sas[sa_slot].configured = true;
    }
}

int ccsds_sdls_sa_lookup(struct ccsds_sdls_ctx *ctx, uint16_t spi,
                         struct ccsds_sdls_sa **sa)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(sa != NULL, "SDLS SA output is NULL");
    if (spi == 0u || spi > CONFIG_CCSDS_SDLS_MAX_SA ||
        !ctx->sas[spi - 1u].configured) {
        *sa = NULL;
        return -ENOENT;
    }

    *sa = &ctx->sas[spi - 1u];
    return 0;
}

int ccsds_sdls_key_lookup(struct ccsds_sdls_ctx *ctx, uint16_t key_id,
                          struct ccsds_sdls_key **key)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(key != NULL, "SDLS key output is NULL");
    if (key_id >= CONFIG_CCSDS_SDLS_MAX_KEYS ||
        ctx->keys[key_id].psa_key_id == PSA_KEY_ID_NULL) {
        *key = NULL;
        return -ENOENT;
    }

    *key = &ctx->keys[key_id];
    return 0;
}

void ccsds_sdls_security_header_encode(
    const struct ccsds_sdls_security_header *header,
    uint8_t out[CCSDS_SDLS_SECURITY_HEADER_LEN])
{
    __ASSERT(header != NULL, "SDLS Security Header is NULL");
    __ASSERT(out != NULL, "SDLS Security Header output is NULL");
    __ASSERT(header->spi != 0u && header->spi != UINT16_MAX,
             "reserved SDLS SPI");

    sys_put_be16(header->spi, out);
    memcpy(out + 2u, header->iv, CCSDS_SDLS_IV_LEN);
}

int ccsds_sdls_security_header_decode(const uint8_t *encoded,
                                      size_t encoded_len,
                                      struct ccsds_sdls_security_header *header)
{
    uint16_t spi;

    __ASSERT(encoded != NULL, "SDLS Security Header input is NULL");
    __ASSERT(header != NULL, "SDLS Security Header output is NULL");

    if (encoded_len != CCSDS_SDLS_SECURITY_HEADER_LEN) {
        return CCSDS_SDLS_ERR_FORMAT;
    }

    spi = sys_get_be16(encoded);
    if (spi == 0u || spi == UINT16_MAX) {
        return CCSDS_SDLS_ERR_FORMAT;
    }

    header->spi = spi;
    memcpy(header->iv, encoded + 2u, CCSDS_SDLS_IV_LEN);
    return 0;
}

void ccsds_sdls_security_trailer_encode(
    const struct ccsds_sdls_security_trailer *trailer,
    uint8_t out[CCSDS_SDLS_SECURITY_TRAILER_LEN])
{
    __ASSERT(trailer != NULL, "SDLS Security Trailer is NULL");
    __ASSERT(out != NULL, "SDLS Security Trailer output is NULL");

    memcpy(out, trailer->tag, CCSDS_SDLS_TAG_LEN);
}

int ccsds_sdls_security_trailer_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_security_trailer *trailer)
{
    __ASSERT(encoded != NULL, "SDLS Security Trailer input is NULL");
    __ASSERT(trailer != NULL, "SDLS Security Trailer output is NULL");

    if (encoded_len != CCSDS_SDLS_SECURITY_TRAILER_LEN) {
        return CCSDS_SDLS_ERR_FORMAT;
    }

    memcpy(trailer->tag, encoded, CCSDS_SDLS_TAG_LEN);
    return 0;
}

void ccsds_sdls_construct_iv(uint64_t sender_iv, uint32_t arsn,
                             uint8_t iv[CCSDS_SDLS_IV_LEN])
{
    __ASSERT(iv != NULL, "SDLS IV output is NULL");

    sys_put_be64(sender_iv, iv);
    sys_put_be32(arsn, iv + 8u);
}

uint32_t ccsds_sdls_iv_arsn(const uint8_t iv[CCSDS_SDLS_IV_LEN])
{
    __ASSERT(iv != NULL, "SDLS IV input is NULL");

    return sys_get_be32(iv + 8u);
}

static int operational_key(struct ccsds_sdls_ctx *ctx, int sa_slot,
                           enum ccsds_sdls_sa_role expected_role,
                           bool transmitting, struct ccsds_sdls_key **key)
{
    struct ccsds_sdls_sa *sa = &ctx->sas[sa_slot];
    bool expected_tx = expected_role == CCSDS_SDLS_SA_EP_REPLY_TX ||
                       expected_role == CCSDS_SDLS_SA_OPERATIONAL_TM_TX;

    if (ctx->sa_roles[sa_slot] != expected_role ||
        expected_tx != transmitting || sa->state != CCSDS_SDLS_SA_OPERATIONAL) {
        return CCSDS_SDLS_ERR_SA_STATE;
    }
    if (sa->key_slot < CONFIG_CCSDS_SDLS_SESSION_KEY_BASE ||
        sa->key_slot >= CONFIG_CCSDS_SDLS_MAX_KEYS) {
        return CCSDS_SDLS_ERR_KEY;
    }

    *key = &ctx->keys[sa->key_slot];
    if ((*key)->state != CCSDS_SDLS_KEY_ACTIVE ||
        (*key)->psa_key_id == PSA_KEY_ID_NULL) {
        return CCSDS_SDLS_ERR_KEY;
    }

    return 0;
}

static size_t build_auth_data(uint8_t *out, struct ccsds_sdls_auth_header auth,
                              uint16_t spi, const uint8_t *frame_data,
                              size_t frame_data_len)
{
    size_t offset = 0u;

    for (; offset < auth.mask_len; offset++) {
        out[offset] = auth.data[offset] & auth.mask[offset];
    }
    if (offset < auth.len) {
        memcpy(out + offset, auth.data + offset, auth.len - offset);
        offset = auth.len;
    }

    sys_put_be16(spi, out + offset);
    offset += 2u;
    memset(out + offset, 0, CCSDS_SDLS_IV_LEN);
    offset += CCSDS_SDLS_IV_LEN;

    if (frame_data_len != 0u) {
        memcpy(out + offset, frame_data, frame_data_len);
        offset += frame_data_len;
    }

    return offset;
}

int ccsds_sdls_apply_security(struct ccsds_sdls_ctx *ctx,
                              enum ccsds_sdls_sa_role expected_role,
                              uint16_t spi, struct ccsds_sdls_auth_header auth,
                              const uint8_t *data, size_t data_len,
                              struct ccsds_sdls_workspace workspace,
                              uint8_t *out, size_t out_capacity)
{
    struct ccsds_sdls_security_header header;
    struct ccsds_sdls_key *key;
    size_t aad_len;
    size_t crypto_len;
    size_t output_len;
    size_t workspace_len;
    uint8_t *crypto_out;
    int index;
    int ret;
    bool gcm;
    psa_status_t status;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(expected_role == CCSDS_SDLS_SA_EP_REPLY_TX ||
                 expected_role == CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
             "ApplySecurity requires a TX role");
    __ASSERT(data != NULL || data_len == 0u, "SDLS clear data is NULL");
    __ASSERT(out != NULL, "SDLS protected output is NULL");
    ASSERT_AUTH_CONTRACT(auth);
    __ASSERT(data_len <= SIZE_MAX - CCSDS_SDLS_PROTECTED_OVERHEAD,
             "SDLS protected length overflows");
    output_len = data_len + CCSDS_SDLS_PROTECTED_OVERHEAD;
    __ASSERT(out_capacity >= output_len, "SDLS protected output is too small");
    __ASSERT(auth.len <= SIZE_MAX - output_len,
             "SDLS workspace length overflows");
    workspace_len = auth.len + output_len;
    __ASSERT(workspace.data != NULL, "SDLS workspace is NULL");
    __ASSERT(workspace.capacity >= workspace_len,
             "SDLS workspace is too small");

    __ASSERT(spi > 0u && spi <= CONFIG_CCSDS_SDLS_MAX_SA,
             "ApplySecurity SPI is outside the configured range");
    index = (int)spi - 1;
    __ASSERT(ctx->sas[index].configured,
             "ApplySecurity references unconfigured SPI");
    ret = operational_key(ctx, index, expected_role, true, &key);
    if (ret != 0) {
        return ret;
    }
    gcm = ctx->sa_modes[index] == CCSDS_SDLS_MODE_GCM;

    header.spi = spi;
    ccsds_sdls_construct_iv(ctx->tx_iv, key->tx_arsn++, header.iv);
    ctx->tx_iv += CCSDS_SDLS_IV_STRIDE;
    aad_len = build_auth_data(workspace.data, auth, spi, gcm ? NULL : data,
                              gcm ? 0u : data_len);
    crypto_out = workspace.data + aad_len;

    status = psa_aead_encrypt(
        key->psa_key_id, PSA_ALG_GCM, header.iv, sizeof(header.iv),
        workspace.data, aad_len, gcm ? data : NULL, gcm ? data_len : 0u,
        crypto_out, gcm ? data_len + CCSDS_SDLS_TAG_LEN : CCSDS_SDLS_TAG_LEN,
        &crypto_len);
    if (status != PSA_SUCCESS ||
        crypto_len !=
            (gcm ? data_len + CCSDS_SDLS_TAG_LEN : CCSDS_SDLS_TAG_LEN)) {
        memset(workspace.data, 0, workspace_len);
        return CCSDS_SDLS_ERR_PSA;
    }

    ccsds_sdls_security_header_encode(&header, out);
    if (gcm) {
        memcpy(out + CCSDS_SDLS_SECURITY_HEADER_LEN, crypto_out, data_len);
        memcpy(out + CCSDS_SDLS_SECURITY_HEADER_LEN + data_len,
               crypto_out + data_len, CCSDS_SDLS_TAG_LEN);
    } else {
        memmove(out + CCSDS_SDLS_SECURITY_HEADER_LEN, data, data_len);
        memcpy(out + CCSDS_SDLS_SECURITY_HEADER_LEN + data_len, crypto_out,
               CCSDS_SDLS_TAG_LEN);
    }

    memset(workspace.data, 0, workspace_len);
    return 0;
}

int ccsds_sdls_process_security(struct ccsds_sdls_ctx *ctx,
                                enum ccsds_sdls_sa_role expected_role,
                                struct ccsds_sdls_auth_header auth,
                                const uint8_t *protected_data,
                                size_t protected_len,
                                struct ccsds_sdls_workspace workspace,
                                uint8_t *out, size_t out_capacity)
{
    struct ccsds_sdls_security_header header;
    struct ccsds_sdls_key *key;
    struct ccsds_sdls_sa *sa;
    const uint8_t *frame_data;
    const uint8_t *tag;
    size_t aad_len;
    size_t data_len;
    size_t plaintext_len = 0u;
    size_t workspace_len;
    uint8_t dummy = 0u;
    uint8_t *plaintext;
    uint32_t arsn;
    uint32_t advance;
    int index;
    int ret;
    bool gcm;
    psa_status_t status;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(expected_role == CCSDS_SDLS_SA_EP_COMMAND_RX ||
                 expected_role == CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             "ProcessSecurity requires an RX role");
    __ASSERT(protected_data != NULL, "SDLS protected input is NULL");
    __ASSERT(out != NULL, "SDLS clear output is NULL");
    ASSERT_AUTH_CONTRACT(auth);

    if (protected_len < CCSDS_SDLS_PROTECTED_OVERHEAD) {
        return CCSDS_SDLS_ERR_FORMAT;
    }
    data_len = protected_len - CCSDS_SDLS_PROTECTED_OVERHEAD;
    __ASSERT(out_capacity >= data_len, "SDLS clear output is too small");
    __ASSERT(auth.len <= SIZE_MAX - CCSDS_SDLS_SECURITY_HEADER_LEN - data_len,
             "SDLS workspace length overflows");
    workspace_len = auth.len + CCSDS_SDLS_SECURITY_HEADER_LEN + data_len;
    __ASSERT(workspace.data != NULL, "SDLS workspace is NULL");
    __ASSERT(workspace.capacity >= workspace_len,
             "SDLS workspace is too small");

    ret = ccsds_sdls_security_header_decode(
        protected_data, CCSDS_SDLS_SECURITY_HEADER_LEN, &header);
    if (ret != 0) {
        return ret;
    }
    if (header.spi > CONFIG_CCSDS_SDLS_MAX_SA ||
        !ctx->sas[header.spi - 1u].configured) {
        return CCSDS_SDLS_ERR_UNKNOWN_SA;
    }
    index = (int)header.spi - 1;
    ret = operational_key(ctx, index, expected_role, false, &key);
    if (ret != 0) {
        return ret;
    }
    sa = &ctx->sas[index];
    gcm = ctx->sa_modes[index] == CCSDS_SDLS_MODE_GCM;

    arsn = ccsds_sdls_iv_arsn(header.iv);
    if (sa->rx_arsn_initialized) {
        if (arsn <= sa->rx_arsn) {
            return CCSDS_SDLS_ERR_REPLAY;
        }
        advance = arsn - sa->rx_arsn;
        if (advance > CONFIG_CCSDS_SDLS_ARSN_WINDOW) {
            return CCSDS_SDLS_ERR_REPLAY;
        }
    }

    frame_data = protected_data + CCSDS_SDLS_SECURITY_HEADER_LEN;
    tag = frame_data + data_len;
    aad_len = build_auth_data(workspace.data, auth, header.spi,
                              gcm ? NULL : frame_data, gcm ? 0u : data_len);
    plaintext = gcm ? workspace.data + aad_len : &dummy;

    status = psa_aead_decrypt(
        key->psa_key_id, PSA_ALG_GCM, header.iv, sizeof(header.iv),
        workspace.data, aad_len, gcm ? frame_data : tag,
        gcm ? data_len + CCSDS_SDLS_TAG_LEN : CCSDS_SDLS_TAG_LEN, plaintext,
        gcm ? data_len : sizeof(dummy), &plaintext_len);
    if (status != PSA_SUCCESS) {
        memset(workspace.data, 0, workspace_len);
        return status == PSA_ERROR_INVALID_SIGNATURE
                   ? CCSDS_SDLS_ERR_AUTHENTICATION
                   : CCSDS_SDLS_ERR_PSA;
    }
    if (plaintext_len != (gcm ? data_len : 0u)) {
        memset(workspace.data, 0, workspace_len);
        return CCSDS_SDLS_ERR_PSA;
    }

    memmove(out, gcm ? plaintext : frame_data, data_len);
    sa->rx_arsn = arsn;
    sa->rx_arsn_initialized = true;
    memset(workspace.data, 0, workspace_len);
    return 0;
}
