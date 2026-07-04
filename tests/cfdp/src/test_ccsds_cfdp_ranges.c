#include <zephyr/ztest.h>

#include "ccsds/ccsds_cfdp_ranges.h"

static void assert_range(const ccsds_cfdp_ranges_t *ranges, size_t index,
                         uint32_t start, uint32_t end)
{
    zassert_true(index < ranges->count);
    zassert_equal(ranges->ranges[index].start, start);
    zassert_equal(ranges->ranges[index].end, end);
}

static bool is_complete(const ccsds_cfdp_ranges_t *ranges, uint32_t start,
                        uint32_t end)
{
    bool complete = false;

    zassert_equal(ccsds_cfdp_ranges_is_complete(ranges, start, end, &complete),
                  CCSDS_CFDP_STATUS_OK);
    return complete;
}

ZTEST(ccsds_cfdp_ranges, test_in_order_ranges)
{
    ccsds_cfdp_ranges_t ranges;

    zassert_equal(ccsds_cfdp_ranges_init(&ranges), CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 0u, 4u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 4u, 8u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 8u, 12u),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(ranges.count, 1u);
    assert_range(&ranges, 0u, 0u, 12u);
    zassert_true(is_complete(&ranges, 0u, 12u));
}

ZTEST(ccsds_cfdp_ranges, test_out_of_order_ranges)
{
    ccsds_cfdp_ranges_t ranges;

    zassert_equal(ccsds_cfdp_ranges_init(&ranges), CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 8u, 12u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 0u, 4u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 4u, 8u),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(ranges.count, 1u);
    assert_range(&ranges, 0u, 0u, 12u);
    zassert_true(is_complete(&ranges, 0u, 12u));
}

ZTEST(ccsds_cfdp_ranges, test_overlapping_ranges)
{
    ccsds_cfdp_ranges_t ranges;

    zassert_equal(ccsds_cfdp_ranges_init(&ranges), CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 10u, 20u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 15u, 25u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 5u, 12u),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(ranges.count, 1u);
    assert_range(&ranges, 0u, 5u, 25u);
    zassert_true(is_complete(&ranges, 10u, 20u));
}

ZTEST(ccsds_cfdp_ranges, test_adjacent_range_merge)
{
    ccsds_cfdp_ranges_t ranges;

    zassert_equal(ccsds_cfdp_ranges_init(&ranges), CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 20u, 30u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 10u, 20u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 30u, 40u),
                  CCSDS_CFDP_STATUS_OK);

    zassert_equal(ranges.count, 1u);
    assert_range(&ranges, 0u, 10u, 40u);
}

ZTEST(ccsds_cfdp_ranges, test_missing_ranges_after_eof_style_file_size)
{
    ccsds_cfdp_ranges_t ranges;
    ccsds_cfdp_ranges_t missing;
    const uint32_t file_size = 32u;

    zassert_equal(ccsds_cfdp_ranges_init(&ranges), CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 0u, 8u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 12u, 20u),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 24u, file_size),
                  CCSDS_CFDP_STATUS_OK);

    zassert_false(is_complete(&ranges, 0u, file_size));
    zassert_equal(ccsds_cfdp_ranges_missing(&ranges, 0u, file_size, &missing),
                  CCSDS_CFDP_STATUS_OK);
    zassert_equal(missing.count, 2u);
    assert_range(&missing, 0u, 8u, 12u);
    assert_range(&missing, 1u, 20u, 24u);
}

ZTEST(ccsds_cfdp_ranges, test_overflow_behavior)
{
    ccsds_cfdp_ranges_t ranges;

    zassert_equal(ccsds_cfdp_ranges_init(&ranges), CCSDS_CFDP_STATUS_OK);

    for (uint32_t i = 0u; i < CCSDS_CFDP_MAX_NAK_RANGES; i++) {
        uint32_t start = i * 10u;

        zassert_equal(ccsds_cfdp_ranges_add(&ranges, start, start + 1u),
                      CCSDS_CFDP_STATUS_OK);
    }

    zassert_equal(ranges.count, CCSDS_CFDP_MAX_NAK_RANGES);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 1000u, 1001u),
                  CCSDS_CFDP_STATUS_BUFFER_TOO_SMALL);
    zassert_equal(ranges.count, CCSDS_CFDP_MAX_NAK_RANGES);
}

ZTEST(ccsds_cfdp_ranges, test_invalid_ranges)
{
    ccsds_cfdp_ranges_t ranges;
    ccsds_cfdp_ranges_t missing;
    bool complete = true;

    zassert_equal(ccsds_cfdp_ranges_init(&ranges), CCSDS_CFDP_STATUS_OK);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 4u, 4u),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_equal(ccsds_cfdp_ranges_add(&ranges, 5u, 4u),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_equal(ccsds_cfdp_ranges_is_complete(&ranges, 9u, 9u, &complete),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
    zassert_equal(ccsds_cfdp_ranges_missing(&ranges, 10u, 2u, &missing),
                  CCSDS_CFDP_STATUS_INVALID_ARGUMENT);
}

ZTEST_SUITE(ccsds_cfdp_ranges, NULL, NULL, NULL, NULL, NULL);
