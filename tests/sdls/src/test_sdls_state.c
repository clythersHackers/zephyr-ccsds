#include <errno.h>
#include <stddef.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <ccsds/ccsds_sdls.h>

BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_SA == 4,
             "footprint proof uses four SA slots");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_KEYS == 8,
             "footprint proof uses eight key slots");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_SESSION_KEY_BASE == 4,
             "lookup proof uses four master-key slots");
BUILD_ASSERT(sizeof(struct ccsds_sdls_sa) == 16,
             "SDLS SA state footprint changed");
BUILD_ASSERT(sizeof(struct ccsds_sdls_key) == 12,
             "SDLS key state footprint changed");
BUILD_ASSERT(CCSDS_SDLS_CONTEXT_STATIC_BYTES ==
                 192u + CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY * 8u + 16u,
             "default SDLS context footprint changed");
BUILD_ASSERT(offsetof(struct ccsds_sdls_ctx, keys) ==
                 sizeof(((struct ccsds_sdls_ctx *)0)->sas),
             "SDLS key slots must follow SA state");

static const struct ccsds_sdls_key_init valid_keys[] = {
    {
        .psa_key_id = 101u,
        .key_id = 4u,
        .state = CCSDS_SDLS_KEY_ACTIVE,
    },
    {
        .psa_key_id = 102u,
        .key_id = 5u,
        .state = CCSDS_SDLS_KEY_PREACTIVE,
    },
};

static const struct ccsds_sdls_sa_init valid_sas[] = {
    {
        .spi = 1u,
        .key_id = 4u,
        .role = CCSDS_SDLS_SA_EP_COMMAND_RX,
        .mode = CCSDS_SDLS_MODE_GMAC,
        .state = CCSDS_SDLS_SA_OPERATIONAL,
        .has_key = true,
        .rx_arsn_initialized = true,
        .rx_arsn = 42u,
    },
    {
        .spi = 2u,
        .role = CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
        .mode = CCSDS_SDLS_MODE_GCM,
        .state = CCSDS_SDLS_SA_STOPPED,
        .has_key = false,
    },
};

ZTEST(sdls_state, test_context_initialization_and_lookup)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_sa *sa;
    struct ccsds_sdls_key *key;

    ccsds_sdls_init(&ctx, valid_sas, ARRAY_SIZE(valid_sas), valid_keys,
                    ARRAY_SIZE(valid_keys));
    zassert_ok(ccsds_sdls_sa_lookup(&ctx, 1u, &sa));
    zassert_equal(sa->state, CCSDS_SDLS_SA_OPERATIONAL);
    zassert_equal(sa->key_slot, 4u);
    zassert_true(sa->rx_arsn_initialized);
    zassert_equal(sa->rx_arsn, 42u);
    zassert_equal(sa->rx_window, CONFIG_CCSDS_SDLS_ARSN_WINDOW);
    zassert_ok(ccsds_sdls_sa_lookup(&ctx, 2u, &sa));
    zassert_equal(sa->key_slot, CCSDS_SDLS_KEY_SLOT_NONE);
    zassert_ok(ccsds_sdls_key_lookup(&ctx, 5u, &key));
    zassert_equal(key->psa_key_id, 102u);
    zassert_equal(key->tx_arsn, 0u);
    zassert_equal(ctx.tx_iv, CCSDS_SDLS_IV_SEED);
    zassert_false(ctx.fsr_enabled);
    zassert_false(ctx.fsr_next);
}

ZTEST(sdls_state, test_unknown_identifiers)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_sa *sa = (void *)1;
    struct ccsds_sdls_key *key = (void *)1;

    ccsds_sdls_init(&ctx, valid_sas, ARRAY_SIZE(valid_sas), valid_keys,
                    ARRAY_SIZE(valid_keys));
    zassert_equal(ccsds_sdls_sa_lookup(&ctx, 0u, &sa), -ENOENT);
    zassert_is_null(sa);
    zassert_equal(ccsds_sdls_sa_lookup(&ctx, 0xffffu, &sa), -ENOENT);
    zassert_is_null(sa);
    zassert_equal(ccsds_sdls_key_lookup(
                      &ctx, CONFIG_CCSDS_SDLS_MAX_KEYS, &key),
                  -ENOENT);
    zassert_is_null(key);
    zassert_equal(ccsds_sdls_key_lookup(&ctx, 0xffffu, &key), -ENOENT);
    zassert_is_null(key);
}

ZTEST_SUITE(sdls_state, NULL, NULL, NULL, NULL, NULL);
