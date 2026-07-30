#include "ccsds_sdls.h"

#include <errno.h>
#include <string.h>

#include <psa/crypto_values.h>
#include <zephyr/sys/__assert.h>

static bool sa_role_valid(enum ccsds_sdls_sa_role role)
{
    return role >= CCSDS_SDLS_SA_EP_COMMAND_RX &&
           role <= CCSDS_SDLS_SA_OPERATIONAL_TM_TX;
}

static bool sa_state_valid(enum ccsds_sdls_sa_state state)
{
    return state >= CCSDS_SDLS_SA_STOPPED &&
           state <= CCSDS_SDLS_SA_EXPIRED;
}

static bool key_role_valid(enum ccsds_sdls_key_role role)
{
    return role >= CCSDS_SDLS_KEY_MASTER &&
           role <= CCSDS_SDLS_KEY_SESSION;
}

static bool key_state_valid(enum ccsds_sdls_key_state state)
{
    return state >= CCSDS_SDLS_KEY_PREACTIVE &&
           state <= CCSDS_SDLS_KEY_DEACTIVATED;
}

static int key_index(const struct ccsds_sdls_ctx *ctx, uint16_t key_id)
{
    for (uint8_t i = 0u; i < ctx->key_count; i++) {
        if (ctx->keys[i].key_id == key_id) {
            return i;
        }
    }

    return -ENOENT;
}

int ccsds_sdls_init(struct ccsds_sdls_ctx *ctx,
                    const struct ccsds_sdls_sa_init *sas, size_t sa_count,
                    const struct ccsds_sdls_key_init *keys, size_t key_count)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(sas != NULL || sa_count == 0u, "SDLS SA configuration is NULL");
    __ASSERT(keys != NULL || key_count == 0u,
             "SDLS key configuration is NULL");

    memset(ctx, 0, sizeof(*ctx));

    if (sa_count > CONFIG_CCSDS_SDLS_MAX_SA ||
        key_count > CONFIG_CCSDS_SDLS_MAX_KEYS) {
        return -ENOSPC;
    }

    for (size_t i = 0u; i < key_count; i++) {
        if (keys[i].psa_key_id == PSA_KEY_ID_NULL ||
            !key_role_valid(keys[i].role) ||
            !key_state_valid(keys[i].state)) {
            memset(ctx, 0, sizeof(*ctx));
            return -EINVAL;
        }
        for (size_t j = 0u; j < i; j++) {
            if (keys[j].key_id == keys[i].key_id) {
                memset(ctx, 0, sizeof(*ctx));
                return -EEXIST;
            }
        }

        ctx->keys[i].psa_key_id = keys[i].psa_key_id;
        ctx->keys[i].key_id = keys[i].key_id;
        ctx->keys[i].role = (uint8_t)keys[i].role;
        ctx->keys[i].state = (uint8_t)keys[i].state;
        ctx->key_count++;
    }

    for (size_t i = 0u; i < sa_count; i++) {
        int slot = -ENOENT;

        if (!sa_role_valid(sas[i].role) || !sa_state_valid(sas[i].state)) {
            goto invalid;
        }
        for (size_t j = 0u; j < i; j++) {
            if (sas[j].spi == sas[i].spi) {
                memset(ctx, 0, sizeof(*ctx));
                return -EEXIST;
            }
        }
        if (sas[i].has_key) {
            slot = key_index(ctx, sas[i].key_id);
            if (slot < 0) {
                memset(ctx, 0, sizeof(*ctx));
                return slot;
            }
        }

        ctx->sa_spis[i] = sas[i].spi;
        ctx->sa_roles[i] = (uint8_t)sas[i].role;
        ctx->sas[i].key_slot =
            sas[i].has_key ? (uint8_t)slot : CCSDS_SDLS_KEY_SLOT_NONE;
        ctx->sas[i].state = (uint8_t)sas[i].state;
        ctx->sas[i].rx_highest_arsn = sas[i].rx_highest_arsn;
        ctx->sas[i].rx_arsn_initialized = sas[i].rx_arsn_initialized;
        ctx->sa_count++;
    }

    return 0;

invalid:
    memset(ctx, 0, sizeof(*ctx));
    return -EINVAL;
}

int ccsds_sdls_sa_lookup(struct ccsds_sdls_ctx *ctx, uint16_t spi,
                         struct ccsds_sdls_sa **sa)
{
    const struct ccsds_sdls_sa *found;
    int ret;

    __ASSERT(sa != NULL, "SDLS SA output is NULL");
    ret = ccsds_sdls_sa_lookup_const(ctx, spi, &found);
    *sa = ret == 0 ? &ctx->sas[found - ctx->sas] : NULL;
    return ret;
}

int ccsds_sdls_sa_lookup_const(const struct ccsds_sdls_ctx *ctx, uint16_t spi,
                               const struct ccsds_sdls_sa **sa)
{
    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(sa != NULL, "SDLS SA output is NULL");

    *sa = NULL;
    for (uint8_t i = 0u; i < ctx->sa_count; i++) {
        if (ctx->sa_spis[i] == spi) {
            *sa = &ctx->sas[i];
            return 0;
        }
    }

    return -ENOENT;
}

int ccsds_sdls_key_lookup(struct ccsds_sdls_ctx *ctx, uint16_t key_id,
                          struct ccsds_sdls_key **key)
{
    const struct ccsds_sdls_key *found;
    int ret;

    __ASSERT(key != NULL, "SDLS key output is NULL");
    ret = ccsds_sdls_key_lookup_const(ctx, key_id, &found);
    *key = ret == 0 ? &ctx->keys[found - ctx->keys] : NULL;
    return ret;
}

int ccsds_sdls_key_lookup_const(const struct ccsds_sdls_ctx *ctx,
                                uint16_t key_id,
                                const struct ccsds_sdls_key **key)
{
    int index;

    __ASSERT(ctx != NULL, "SDLS context is NULL");
    __ASSERT(key != NULL, "SDLS key output is NULL");

    *key = NULL;
    index = key_index(ctx, key_id);
    if (index < 0) {
        return index;
    }

    *key = &ctx->keys[index];
    return 0;
}
