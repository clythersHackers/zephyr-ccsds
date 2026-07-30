#include <errno.h>
#include <stddef.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <ccsds/ccsds_sdls.h>

BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_SA == 4,
             "Stage 1 footprint proof uses the default four SA slots");
BUILD_ASSERT(CONFIG_CCSDS_SDLS_MAX_KEYS == 8,
             "Stage 1 footprint proof uses the default eight key slots");
BUILD_ASSERT(sizeof(struct ccsds_sdls_sa) == 8,
             "Stage 1 SA mutable state footprint changed");
BUILD_ASSERT(sizeof(struct ccsds_sdls_key) == 8,
             "Stage 1 opaque key metadata footprint changed");
BUILD_ASSERT(CCSDS_SDLS_CONTEXT_STATIC_BYTES == 112,
             "Stage 1 default context footprint changed");
BUILD_ASSERT(offsetof(struct ccsds_sdls_ctx, keys) ==
                 sizeof(((struct ccsds_sdls_ctx *)0)->sas),
             "SDLS key slots must immediately follow inline SA state");

static const struct ccsds_sdls_key_init valid_keys[] = {
    {
        .psa_key_id = 101u,
        .key_id = 0x1001u,
        .role = CCSDS_SDLS_KEY_MASTER,
        .state = CCSDS_SDLS_KEY_ACTIVE,
    },
    {
        .psa_key_id = 102u,
        .key_id = 0x1002u,
        .role = CCSDS_SDLS_KEY_SESSION,
        .state = CCSDS_SDLS_KEY_PREACTIVE,
    },
};

static const struct ccsds_sdls_sa_init valid_sas[] = {
    {
        .spi = 0x0021u,
        .key_id = 0x1001u,
        .role = CCSDS_SDLS_SA_EP_COMMAND_RX,
        .state = CCSDS_SDLS_SA_OPERATIONAL,
        .has_key = true,
        .rx_arsn_initialized = true,
        .rx_highest_arsn = 42u,
    },
    {
        .spi = 0x0022u,
        .role = CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
        .state = CCSDS_SDLS_SA_STOPPED,
        .has_key = false,
    },
};

ZTEST(sdls_state, test_context_initialization_and_lookup)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_sa *sa;
    struct ccsds_sdls_key *key;

    zassert_ok(ccsds_sdls_init(&ctx, valid_sas, ARRAY_SIZE(valid_sas),
                               valid_keys, ARRAY_SIZE(valid_keys)));
    zassert_equal(ctx.sa_count, ARRAY_SIZE(valid_sas));
    zassert_equal(ctx.key_count, ARRAY_SIZE(valid_keys));
    zassert_ok(ccsds_sdls_sa_lookup(&ctx, 0x0021u, &sa));
    zassert_equal(sa->state, CCSDS_SDLS_SA_OPERATIONAL);
    zassert_equal(sa->key_slot, 0u);
    zassert_true(sa->rx_arsn_initialized);
    zassert_equal(sa->rx_highest_arsn, 42u);
    zassert_ok(ccsds_sdls_sa_lookup(&ctx, 0x0022u, &sa));
    zassert_equal(sa->key_slot, CCSDS_SDLS_KEY_SLOT_NONE);
    zassert_ok(ccsds_sdls_key_lookup(&ctx, 0x1002u, &key));
    zassert_equal(key->psa_key_id, 102u);
    zassert_equal(key->role, CCSDS_SDLS_KEY_SESSION);
}

ZTEST(sdls_state, test_unknown_identifiers)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_sa *sa = (void *)1;
    struct ccsds_sdls_key *key = (void *)1;

    zassert_ok(ccsds_sdls_init(&ctx, valid_sas, ARRAY_SIZE(valid_sas),
                               valid_keys, ARRAY_SIZE(valid_keys)));
    zassert_equal(ccsds_sdls_sa_lookup(&ctx, 0xffffu, &sa), -ENOENT);
    zassert_is_null(sa);
    zassert_equal(ccsds_sdls_key_lookup(&ctx, 0xffffu, &key), -ENOENT);
    zassert_is_null(key);
}

ZTEST(sdls_state, test_duplicate_identifiers_leave_empty_context)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_key_init duplicate_keys[2] = {
        valid_keys[0], valid_keys[1]
    };
    struct ccsds_sdls_sa_init duplicate_sas[2] = {
        valid_sas[0], valid_sas[1]
    };

    duplicate_keys[1].key_id = duplicate_keys[0].key_id;
    zassert_equal(ccsds_sdls_init(&ctx, NULL, 0u, duplicate_keys,
                                  ARRAY_SIZE(duplicate_keys)),
                  -EEXIST);
    zassert_equal(ctx.sa_count, 0u);
    zassert_equal(ctx.key_count, 0u);

    duplicate_sas[1].spi = duplicate_sas[0].spi;
    zassert_equal(ccsds_sdls_init(&ctx, duplicate_sas,
                                  ARRAY_SIZE(duplicate_sas), valid_keys,
                                  ARRAY_SIZE(valid_keys)),
                  -EEXIST);
    zassert_equal(ctx.sa_count, 0u);
    zassert_equal(ctx.key_count, 0u);
}

ZTEST(sdls_state, test_fixed_capacity_exhaustion)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_key_init
        keys[CONFIG_CCSDS_SDLS_MAX_KEYS + 1u] = { 0 };
    struct ccsds_sdls_sa_init sas[CONFIG_CCSDS_SDLS_MAX_SA + 1u] = { 0 };

    zassert_equal(ccsds_sdls_init(&ctx, NULL, 0u, keys, ARRAY_SIZE(keys)),
                  -ENOSPC);
    zassert_equal(ctx.key_count, 0u);
    zassert_equal(ccsds_sdls_init(&ctx, sas, ARRAY_SIZE(sas), NULL, 0u),
                  -ENOSPC);
    zassert_equal(ctx.sa_count, 0u);
}

ZTEST(sdls_state, test_unknown_sa_key_reference)
{
    struct ccsds_sdls_ctx ctx;
    struct ccsds_sdls_sa_init sa = valid_sas[0];

    sa.key_id = 0xeeeeu;
    zassert_equal(ccsds_sdls_init(&ctx, &sa, 1u, valid_keys,
                                  ARRAY_SIZE(valid_keys)),
                  -ENOENT);
    zassert_equal(ctx.sa_count, 0u);
    zassert_equal(ctx.key_count, 0u);
}

ZTEST_SUITE(sdls_state, NULL, NULL, NULL, NULL, NULL);
