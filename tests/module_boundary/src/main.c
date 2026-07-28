/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include <ccsds/ccsds.h>
#include <ccsds/ccsds_udp.h>

#ifndef CCSDS_MODULE_CMAKE_LOADED
#error "CCSDS module CMake integration was not loaded"
#endif

ZTEST(ccsds_module_boundary, test_module_integration)
{
	zassert_true(IS_ENABLED(CONFIG_CCSDS));
	zassert_equal(CCSDS_MODULE_PRESENT, 1);
	zassert_equal(CCSDS_MODULE_CMAKE_LOADED, 1);
}

static int count_unit(void *user, const uint8_t *unit, size_t unit_len)
{
	uint32_t *count = user;

	zassert_not_null(unit);
	zassert_true(unit_len > 0u);
	(*count)++;
	return 0;
}

ZTEST(ccsds_module_boundary, test_udp_instances_keep_independent_state)
{
	struct ccsds_udp a;
	struct ccsds_udp b;
	struct ccsds_udp_stats a_stats;
	struct ccsds_udp_stats b_stats;
	uint32_t a_calls = 0u;
	uint32_t b_calls = 0u;
	const uint8_t unit[] = {0x01u};
	struct ccsds_udp_config config = {
		.local_ip = "127.0.0.1",
		.local_port = 5005u,
		.peer_ip = "127.0.0.1",
		.peer_port = 5006u,
		.max_unit_len = 32u,
		.thread_priority = 14,
		.receive = count_unit,
		.receive_user = &a_calls,
	};

	zassert_ok(ccsds_udp_init(&a, &config));
	config.local_port = 5006u;
	config.peer_port = 5005u;
	config.receive_user = &b_calls;
	zassert_ok(ccsds_udp_init(&b, &config));

	zassert_ok(ccsds_udp_dispatch_datagram(&a, unit, sizeof(unit)));
	zassert_ok(ccsds_udp_dispatch_datagram(&a, unit, sizeof(unit)));
	zassert_ok(ccsds_udp_dispatch_datagram(&b, unit, sizeof(unit)));
	ccsds_udp_get_stats(&a, &a_stats);
	ccsds_udp_get_stats(&b, &b_stats);

	zassert_equal(a_calls, 2u);
	zassert_equal(b_calls, 1u);
	zassert_equal(a_stats.datagrams_received, 2u);
	zassert_equal(b_stats.datagrams_received, 1u);
	zassert_not_equal(&a.lock, &b.lock);
	zassert_not_equal(a.unit_buf, b.unit_buf);
}

ZTEST_SUITE(ccsds_module_boundary, NULL, NULL, NULL, NULL, NULL);
