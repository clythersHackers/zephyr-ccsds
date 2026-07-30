/**
 * @file ccsds_sdls.h
 * @brief Fixed-capacity CCSDS SDLS state foundation.
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
#define CCSDS_SDLS_SPI_BITS 16u
#define CCSDS_SDLS_KEY_ID_BITS 16u
#define CCSDS_SDLS_ARSN_BITS 32u
#define CCSDS_SDLS_KEY_SLOT_NONE UINT8_MAX

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

enum ccsds_sdls_key_role {
    CCSDS_SDLS_KEY_MASTER = 0,
    CCSDS_SDLS_KEY_SESSION,
};

enum ccsds_sdls_key_state {
    CCSDS_SDLS_KEY_PREACTIVE = 0,
    CCSDS_SDLS_KEY_ACTIVE,
    CCSDS_SDLS_KEY_DEACTIVATED,
};

/**
 * Mutable state for one statically configured Security Association.
 *
 * SPI and role are immutable context configuration and intentionally live in
 * separate context arrays. PSA key identifiers live only in the key table.
 */
struct ccsds_sdls_sa {
    uint32_t rx_highest_arsn;
    uint8_t key_slot;
    uint8_t state;
    bool rx_arsn_initialized;
};

/** Fixed key-slot metadata. This structure never contains operational bytes. */
struct ccsds_sdls_key {
    psa_key_id_t psa_key_id;
    uint16_t key_id;
    uint8_t role;
    uint8_t state;
};

struct ccsds_sdls_sa_init {
    uint16_t spi;
    uint16_t key_id;
    uint32_t rx_highest_arsn;
    enum ccsds_sdls_sa_role role;
    enum ccsds_sdls_sa_state state;
    bool has_key;
    bool rx_arsn_initialized;
};

struct ccsds_sdls_key_init {
    psa_key_id_t psa_key_id;
    uint16_t key_id;
    enum ccsds_sdls_key_role role;
    enum ccsds_sdls_key_state state;
};

/**
 * Caller-owned SDLS state. All capacity is compiled into this object.
 *
 * Context initialization copies identifiers and metadata, not key material.
 */
struct ccsds_sdls_ctx {
    struct ccsds_sdls_sa sas[CONFIG_CCSDS_SDLS_MAX_SA];
    struct ccsds_sdls_key keys[CONFIG_CCSDS_SDLS_MAX_KEYS];
    uint16_t sa_spis[CONFIG_CCSDS_SDLS_MAX_SA];
    uint8_t sa_roles[CONFIG_CCSDS_SDLS_MAX_SA];
    uint8_t sa_count;
    uint8_t key_count;
};

#define CCSDS_SDLS_CONTEXT_STATIC_BYTES sizeof(struct ccsds_sdls_ctx)

BUILD_ASSERT(sizeof(((struct ccsds_sdls_key *)0)->key_id) * 8u ==
                 CCSDS_SDLS_KEY_ID_BITS,
             "SDLS key identifiers must be 16 bits");
BUILD_ASSERT(sizeof(((struct ccsds_sdls_ctx *)0)->sa_spis[0]) * 8u ==
                 CCSDS_SDLS_SPI_BITS,
             "SDLS SPIs must be 16 bits");
BUILD_ASSERT(sizeof(((struct ccsds_sdls_sa *)0)->rx_highest_arsn) * 8u ==
                 CCSDS_SDLS_ARSN_BITS,
             "SDLS receive ARSN state must be 32 bits");
BUILD_ASSERT(ARRAY_SIZE(((struct ccsds_sdls_ctx *)0)->sas) ==
                 CONFIG_CCSDS_SDLS_MAX_SA,
             "SDLS SA storage must match CONFIG_CCSDS_SDLS_MAX_SA");
BUILD_ASSERT(ARRAY_SIZE(((struct ccsds_sdls_ctx *)0)->keys) ==
                 CONFIG_CCSDS_SDLS_MAX_KEYS,
             "SDLS key storage must match CONFIG_CCSDS_SDLS_MAX_KEYS");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_SA <= CCSDS_SDLS_KEY_SLOT_NONE,
             "SDLS SA count must fit its fixed index fields");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_KEYS <= CCSDS_SDLS_KEY_SLOT_NONE,
             "SDLS key count must fit its fixed index fields");

/**
 * Initialize a complete, fixed SDLS configuration.
 *
 * NULL object/configuration pointers are programmer contract violations and
 * are asserted. Duplicate/malformed identifiers and capacity exhaustion are
 * runtime configuration errors. On error, the context remains empty.
 */
int ccsds_sdls_init(struct ccsds_sdls_ctx *ctx,
                    const struct ccsds_sdls_sa_init *sas, size_t sa_count,
                    const struct ccsds_sdls_key_init *keys, size_t key_count);

int ccsds_sdls_sa_lookup(struct ccsds_sdls_ctx *ctx, uint16_t spi,
                         struct ccsds_sdls_sa **sa);
int ccsds_sdls_sa_lookup_const(const struct ccsds_sdls_ctx *ctx, uint16_t spi,
                               const struct ccsds_sdls_sa **sa);
int ccsds_sdls_key_lookup(struct ccsds_sdls_ctx *ctx, uint16_t key_id,
                          struct ccsds_sdls_key **key);
int ccsds_sdls_key_lookup_const(const struct ccsds_sdls_ctx *ctx,
                                uint16_t key_id,
                                const struct ccsds_sdls_key **key);

#ifdef __cplusplus
}
#endif

#endif /* CCSDS_SDLS_H */
