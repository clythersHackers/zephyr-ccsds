/**
 * @file ccsds_sdls.h
 * @brief Fixed-profile CCSDS SDLS wire processing.
 */

#ifndef CCSDS_SDLS_H
#define CCSDS_SDLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <psa/crypto_types.h>
#include <zephyr/sys/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CCSDS_SDLS_AES_KEY_BITS 256u
#define CCSDS_SDLS_IV_LEN 12u
#define CCSDS_SDLS_TAG_LEN 16u
#define CCSDS_SDLS_SECURITY_HEADER_LEN 14u
#define CCSDS_SDLS_SECURITY_TRAILER_LEN CCSDS_SDLS_TAG_LEN
#define CCSDS_SDLS_PROTECTED_OVERHEAD                                          \
    (CCSDS_SDLS_SECURITY_HEADER_LEN + CCSDS_SDLS_SECURITY_TRAILER_LEN)
#define CCSDS_SDLS_KEY_SLOT_NONE UINT8_MAX

/* CCSDS 355.1-B-1 annex D fixed Key Management profile. */
#define CCSDS_SDLS_EP_HEADER_LEN 3u
#define CCSDS_SDLS_EP_KEY_LEN 32u
#define CCSDS_SDLS_EP_CHALLENGE_LEN 16u
#define CCSDS_SDLS_EP_OTAR_BLOCK_LEN (2u + CCSDS_SDLS_EP_KEY_LEN)
#define CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN                                 \
    (2u + CCSDS_SDLS_EP_CHALLENGE_LEN)
#define CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN                                   \
    (2u + CCSDS_SDLS_IV_LEN + CCSDS_SDLS_EP_CHALLENGE_LEN + CCSDS_SDLS_TAG_LEN)
#define CCSDS_SDLS_EP_MAX_OTAR_KEYS                                            \
    (CONFIG_CCSDS_SDLS_MAX_KEYS - CONFIG_CCSDS_SDLS_SESSION_KEY_BASE)
#define CCSDS_SDLS_EP_MAX_RECIPIENTS CONFIG_CCSDS_SDLS_MAX_KEYS
#define CCSDS_SDLS_EP_OTAR_DATA_MAX                                            \
    (2u + CCSDS_SDLS_IV_LEN +                                                  \
     CCSDS_SDLS_EP_MAX_OTAR_KEYS * CCSDS_SDLS_EP_OTAR_BLOCK_LEN +              \
     CCSDS_SDLS_TAG_LEN)
#define CCSDS_SDLS_EP_OTAR_PDU_MAX                                             \
    (CCSDS_SDLS_EP_HEADER_LEN + CCSDS_SDLS_EP_OTAR_DATA_MAX)
#define CCSDS_SDLS_EP_KEY_COMMAND_PDU_MAX                                      \
    (CCSDS_SDLS_EP_HEADER_LEN + 2u * CCSDS_SDLS_EP_MAX_RECIPIENTS)
#define CCSDS_SDLS_EP_VERIFY_COMMAND_PDU_MAX                                   \
    (CCSDS_SDLS_EP_HEADER_LEN +                                                \
     CCSDS_SDLS_EP_VERIFY_COMMAND_ENTRY_LEN * CCSDS_SDLS_EP_MAX_RECIPIENTS)
#define CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX                                     \
    (CCSDS_SDLS_EP_HEADER_LEN +                                                \
     CCSDS_SDLS_EP_VERIFY_REPLY_ENTRY_LEN * CCSDS_SDLS_EP_MAX_RECIPIENTS)
#define CCSDS_SDLS_EP_PLAINTEXT_MAX                                            \
    (CCSDS_SDLS_EP_MAX_OTAR_KEYS * CCSDS_SDLS_EP_OTAR_BLOCK_LEN)
#define CCSDS_SDLS_EP_WORKSPACE_MIN                                            \
    MAX(CCSDS_SDLS_EP_PLAINTEXT_MAX, CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX)

/*
 * CCSDS 355.0-B-2 default authentication masks for the fixed TM and TC
 * primary headers. These are compact prefixes: bytes after the array
 * are implicitly 0xff. A TC Segment Header following the five-byte primary
 * header is therefore authenticated without another stored mask byte.
 */
#define CCSDS_SDLS_TM_DEFAULT_AUTH_MASK_LEN 6u
#define CCSDS_SDLS_TC_DEFAULT_AUTH_MASK_LEN 5u

extern const uint8_t
    ccsds_sdls_tm_default_auth_mask[CCSDS_SDLS_TM_DEFAULT_AUTH_MASK_LEN];
extern const uint8_t
    ccsds_sdls_tc_default_auth_mask[CCSDS_SDLS_TC_DEFAULT_AUTH_MASK_LEN];

/*
 * Odd 64-bit golden-ratio Weyl increment. It disperses consecutive sender-IV
 * values; it is not a random-number generator.
 */
#define CCSDS_SDLS_IV_STRIDE UINT64_C(0x9e3779b97f4a7c15)
#define CCSDS_SDLS_IV_SEED                                                     \
    (((uint64_t)CONFIG_CCSDS_SDLS_IV_SEED_HIGH << 32) |                        \
     (uint64_t)CONFIG_CCSDS_SDLS_IV_SEED_LOW)

/* Stable errors for received state and recoverable PSA/runtime failures. */
enum ccsds_sdls_error {
    CCSDS_SDLS_ERR_FORMAT = -1000,
    CCSDS_SDLS_ERR_AUTHENTICATION = -1001,
    CCSDS_SDLS_ERR_REPLAY = -1002,
    CCSDS_SDLS_ERR_UNKNOWN_SA = -1003,
    CCSDS_SDLS_ERR_SA_STATE = -1004,
    CCSDS_SDLS_ERR_KEY = -1005,
    CCSDS_SDLS_ERR_PSA = -1006,
    CCSDS_SDLS_ERR_UNSUPPORTED = -1007,
    CCSDS_SDLS_ERR_KEY_STATE = -1008,
    CCSDS_SDLS_ERR_CAPACITY = -1009,
};

enum ccsds_sdls_ep_procedure {
    CCSDS_SDLS_EP_OTAR = 1,
    CCSDS_SDLS_EP_KEY_ACTIVATION = 2,
    CCSDS_SDLS_EP_KEY_DEACTIVATION = 3,
    CCSDS_SDLS_EP_KEY_VERIFICATION = 4,
};

enum ccsds_sdls_ep_type {
    CCSDS_SDLS_EP_COMMAND = 0,
    CCSDS_SDLS_EP_REPLY = 1,
};

enum ccsds_sdls_sa_state {
    CCSDS_SDLS_SA_STOPPED = 0,
    CCSDS_SDLS_SA_OPERATIONAL,
    CCSDS_SDLS_SA_EXPIRED,
};

enum ccsds_sdls_sa_role {
    CCSDS_SDLS_SA_EP_COMMAND_RX = 0,
    CCSDS_SDLS_SA_EP_REPLY_TX,
    CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
    CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
};

enum ccsds_sdls_security_mode {
    CCSDS_SDLS_MODE_GMAC = 0,
    CCSDS_SDLS_MODE_GCM,
};

enum ccsds_sdls_key_state {
    CCSDS_SDLS_KEY_PREACTIVE = 0,
    CCSDS_SDLS_KEY_ACTIVE,
    CCSDS_SDLS_KEY_DEACTIVATED,
};

struct ccsds_sdls_security_header {
    uint16_t spi;
    uint8_t iv[CCSDS_SDLS_IV_LEN];
};

struct ccsds_sdls_security_trailer {
    uint8_t tag[CCSDS_SDLS_TAG_LEN];
};

/** Mutable state for one predefined Security Association. */
struct ccsds_sdls_sa {
    uint32_t rx_arsn;
    uint8_t key_slot;
    uint8_t state;
    bool rx_arsn_initialized;
    bool configured;
};

/** Opaque PSA key reference and its volatile transmit ARSN. */
struct ccsds_sdls_key {
    psa_key_id_t psa_key_id;
    uint32_t tx_arsn;
    uint8_t state;
};

struct ccsds_sdls_sa_init {
    uint16_t spi;
    uint16_t key_id;
    uint32_t rx_arsn;
    enum ccsds_sdls_sa_role role;
    enum ccsds_sdls_security_mode mode;
    enum ccsds_sdls_sa_state state;
    bool has_key;
    bool rx_arsn_initialized;
};

struct ccsds_sdls_key_init {
    psa_key_id_t psa_key_id;
    uint16_t key_id;
    enum ccsds_sdls_key_state state;
};

/**
 * Transfer-frame bytes preceding the Security Header.
 *
 * Only the mask prefix through the final zero bit needs to be supplied.
 * Bytes beyond mask_len are implicitly masked with all ones. A zero mask
 * length therefore authenticates the complete header unchanged.
 */
struct ccsds_sdls_auth_header {
    const uint8_t *data;
    const uint8_t *mask;
    size_t len;
    size_t mask_len;
};

/** Caller-owned temporary storage. Contents are wiped after use. */
struct ccsds_sdls_workspace {
    uint8_t *data;
    size_t capacity;
};

/** Decoded common EP header. data aliases the caller-owned encoded PDU. */
struct ccsds_sdls_ep_pdu {
    const uint8_t *data;
    size_t data_len;
    uint8_t procedure;
    uint8_t type;
};

/** Ciphertext-only OTAR representation; no plaintext keys are exposed. */
struct ccsds_sdls_ep_otar {
    uint8_t encrypted_key_blocks[CCSDS_SDLS_EP_PLAINTEXT_MAX];
    uint8_t iv[CCSDS_SDLS_IV_LEN];
    uint8_t tag[CCSDS_SDLS_TAG_LEN];
    uint16_t master_key_id;
    size_t key_count;
};

struct ccsds_sdls_ep_key_command {
    uint16_t key_ids[CCSDS_SDLS_EP_MAX_RECIPIENTS];
    size_t key_count;
};

struct ccsds_sdls_ep_verify_command_entry {
    uint8_t challenge[CCSDS_SDLS_EP_CHALLENGE_LEN];
    uint16_t key_id;
};

struct ccsds_sdls_ep_verify_command {
    struct ccsds_sdls_ep_verify_command_entry
        entries[CCSDS_SDLS_EP_MAX_RECIPIENTS];
    size_t key_count;
};

struct ccsds_sdls_ep_verify_reply_entry {
    uint8_t iv[CCSDS_SDLS_IV_LEN];
    uint8_t encrypted_challenge[CCSDS_SDLS_EP_CHALLENGE_LEN];
    uint8_t tag[CCSDS_SDLS_TAG_LEN];
    uint16_t key_id;
};

struct ccsds_sdls_ep_verify_reply {
    struct ccsds_sdls_ep_verify_reply_entry
        entries[CCSDS_SDLS_EP_MAX_RECIPIENTS];
    size_t key_count;
};

/** Caller-owned fixed-capacity SDLS state. */
struct ccsds_sdls_ctx {
    struct ccsds_sdls_sa sas[CONFIG_CCSDS_SDLS_MAX_SA];
    struct ccsds_sdls_key keys[CONFIG_CCSDS_SDLS_MAX_KEYS];
    uint8_t sa_roles[CONFIG_CCSDS_SDLS_MAX_SA];
    uint8_t sa_modes[CONFIG_CCSDS_SDLS_MAX_SA];
    uint64_t tx_iv;
};

#define CCSDS_SDLS_CONTEXT_STATIC_BYTES sizeof(struct ccsds_sdls_ctx)

BUILD_ASSERT(sizeof(((struct ccsds_sdls_sa *)0)->rx_arsn) == 4u,
             "SDLS receive ARSN must be 32 bits");
BUILD_ASSERT(sizeof(((struct ccsds_sdls_key *)0)->tx_arsn) == 4u,
             "SDLS transmit ARSN must be 32 bits");
BUILD_ASSERT(CCSDS_SDLS_IV_LEN == 12u, "SDLS profile requires a 96-bit IV");
BUILD_ASSERT(CCSDS_SDLS_TAG_LEN == 16u, "SDLS profile requires a 128-bit tag");
BUILD_ASSERT(CCSDS_SDLS_SECURITY_HEADER_LEN == 2u + CCSDS_SDLS_IV_LEN,
             "SDLS Security Header length changed");
BUILD_ASSERT((CCSDS_SDLS_IV_STRIDE & UINT64_C(1)) != 0u,
             "SDLS IV stride must be odd");
BUILD_ASSERT(ARRAY_SIZE(((struct ccsds_sdls_ctx *)0)->sas) ==
                 CONFIG_CCSDS_SDLS_MAX_SA,
             "SDLS SA capacity mismatch");
BUILD_ASSERT(ARRAY_SIZE(((struct ccsds_sdls_ctx *)0)->keys) ==
                 CONFIG_CCSDS_SDLS_MAX_KEYS,
             "SDLS key capacity mismatch");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_SA <= CCSDS_SDLS_KEY_SLOT_NONE,
             "SDLS SA count must fit its slot fields");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_KEYS <= CCSDS_SDLS_KEY_SLOT_NONE,
             "SDLS key count must fit its slot fields");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_SESSION_KEY_BASE > 0,
             "SDLS profile requires at least one master-key slot");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_SESSION_KEY_BASE <
                 CONFIG_CCSDS_SDLS_MAX_KEYS,
             "SDLS profile requires at least one session-key slot");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_ARSN_WINDOW > 0,
             "SDLS receive ARSN window must be nonzero");
BUILD_ASSERT(CCSDS_SDLS_EP_OTAR_DATA_MAX <= UINT16_MAX / 8u,
             "SDLS EP OTAR bit length must fit 16 bits");
BUILD_ASSERT(CCSDS_SDLS_EP_VERIFY_REPLY_PDU_MAX - CCSDS_SDLS_EP_HEADER_LEN <=
                 UINT16_MAX / 8u,
             "SDLS EP verification bit length must fit 16 bits");
BUILD_ASSERT(CCSDS_SDLS_EP_MAX_OTAR_KEYS > 0u,
             "SDLS EP requires a session-key slot");

/**
 * Initialize fixed SDLS state.
 *
 * The complete configuration is a programmer-owned compile-time contract;
 * SAs are placed at spi - 1 and keys at key_id. Malformed configuration,
 * duplicate IDs, and capacity overflow assert.
 */
void ccsds_sdls_init(struct ccsds_sdls_ctx *ctx,
                     const struct ccsds_sdls_sa_init *sas, size_t sa_count,
                     const struct ccsds_sdls_key_init *keys, size_t key_count);

int ccsds_sdls_sa_lookup(struct ccsds_sdls_ctx *ctx, uint16_t spi,
                         struct ccsds_sdls_sa **sa);
int ccsds_sdls_key_lookup(struct ccsds_sdls_ctx *ctx, uint16_t key_id,
                          struct ccsds_sdls_key **key);

void ccsds_sdls_security_header_encode(
    const struct ccsds_sdls_security_header *header,
    uint8_t out[CCSDS_SDLS_SECURITY_HEADER_LEN]);
int ccsds_sdls_security_header_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_security_header *header);
void ccsds_sdls_security_trailer_encode(
    const struct ccsds_sdls_security_trailer *trailer,
    uint8_t out[CCSDS_SDLS_SECURITY_TRAILER_LEN]);
int ccsds_sdls_security_trailer_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_security_trailer *trailer);

void ccsds_sdls_construct_iv(uint64_t sender_iv, uint32_t arsn,
                             uint8_t iv[CCSDS_SDLS_IV_LEN]);
uint32_t ccsds_sdls_iv_arsn(const uint8_t iv[CCSDS_SDLS_IV_LEN]);

/**
 * Protect one frame-data span.
 *
 * Output size is data_len + CCSDS_SDLS_PROTECTED_OVERHEAD. Workspace size is
 * auth.len + output size. Those capacities are caller contracts and assert.
 * A transmit ARSN is consumed before PSA is called, including on PSA failure.
 */
int ccsds_sdls_apply_security(struct ccsds_sdls_ctx *ctx,
                              enum ccsds_sdls_sa_role expected_role,
                              uint16_t spi, struct ccsds_sdls_auth_header auth,
                              const uint8_t *data, size_t data_len,
                              struct ccsds_sdls_workspace workspace,
                              uint8_t *out, size_t out_capacity);

/**
 * Authenticate and optionally decrypt one protected frame-data span.
 *
 * Clear output size is protected_len - CCSDS_SDLS_PROTECTED_OVERHEAD.
 * Workspace size is auth.len + CCSDS_SDLS_SECURITY_HEADER_LEN plus that clear
 * length. Those capacities are caller contracts and assert.
 */
int ccsds_sdls_process_security(struct ccsds_sdls_ctx *ctx,
                                enum ccsds_sdls_sa_role expected_role,
                                struct ccsds_sdls_auth_header auth,
                                const uint8_t *protected_data,
                                size_t protected_len,
                                struct ccsds_sdls_workspace workspace,
                                uint8_t *out, size_t out_capacity);

int ccsds_sdls_ep_pdu_decode(const uint8_t *encoded, size_t encoded_len,
                             struct ccsds_sdls_ep_pdu *pdu);
void ccsds_sdls_ep_otar_encode(const struct ccsds_sdls_ep_otar *otar,
                               uint8_t *out, size_t out_capacity);
int ccsds_sdls_ep_otar_decode(const uint8_t *encoded, size_t encoded_len,
                              struct ccsds_sdls_ep_otar *otar);
void ccsds_sdls_ep_key_command_encode(
    enum ccsds_sdls_ep_procedure procedure,
    const struct ccsds_sdls_ep_key_command *command, uint8_t *out,
    size_t out_capacity);
int ccsds_sdls_ep_key_command_decode(
    const uint8_t *encoded, size_t encoded_len,
    enum ccsds_sdls_ep_procedure expected_procedure,
    struct ccsds_sdls_ep_key_command *command);
void ccsds_sdls_ep_verify_command_encode(
    const struct ccsds_sdls_ep_verify_command *command, uint8_t *out,
    size_t out_capacity);
int ccsds_sdls_ep_verify_command_decode(
    const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_ep_verify_command *command);
void ccsds_sdls_ep_verify_reply_encode(
    const struct ccsds_sdls_ep_verify_reply *reply, uint8_t *out,
    size_t out_capacity);
int ccsds_sdls_ep_verify_reply_decode(const uint8_t *encoded,
                                      size_t encoded_len,
                                      struct ccsds_sdls_ep_verify_reply *reply);

int ccsds_sdls_ep_process_otar(struct ccsds_sdls_ctx *ctx,
                               const uint8_t *encoded, size_t encoded_len,
                               struct ccsds_sdls_workspace workspace);
int ccsds_sdls_ep_process_key_activation(struct ccsds_sdls_ctx *ctx,
                                         const uint8_t *encoded,
                                         size_t encoded_len);
int ccsds_sdls_ep_process_key_deactivation(struct ccsds_sdls_ctx *ctx,
                                           const uint8_t *encoded,
                                           size_t encoded_len);
int ccsds_sdls_ep_process_key_verification(
    struct ccsds_sdls_ctx *ctx, const uint8_t *encoded, size_t encoded_len,
    struct ccsds_sdls_workspace workspace, uint8_t *reply,
    size_t reply_capacity);
int ccsds_sdls_ep_check_key_verification(struct ccsds_sdls_ctx *ctx,
                                         const uint8_t *command,
                                         size_t command_len,
                                         const uint8_t *reply, size_t reply_len,
                                         struct ccsds_sdls_workspace workspace);

#ifdef __cplusplus
}
#endif

#endif /* CCSDS_SDLS_H */
