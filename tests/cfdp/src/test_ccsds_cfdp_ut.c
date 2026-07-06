#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ccsds/ccsds_cfdp_entity.h"

#define LOOPBACK_MAX_PDU_SIZE 32u

struct loopback_ut {
    uint64_t local_entity_id;
    uint64_t now_ms;
    ccsds_cfdp_receive_pdu_cb_t receive;
    void *receive_user;
    bool drop_first_octet_enabled;
    uint8_t drop_first_octet;
    uint32_t sent_count;
    uint32_t delivered_count;
    uint32_t dropped_count;
    uint64_t last_dest_entity_id;
};

struct receive_capture {
    bool called;
    void *expected_user;
    uint64_t source_entity_id;
    uint8_t pdu[LOOPBACK_MAX_PDU_SIZE];
    size_t pdu_len;
};

static int loopback_send_pdu(void *user, uint64_t dest_entity_id,
                             const uint8_t *pdu, size_t pdu_len)
{
    struct loopback_ut *ut = user;

    if (ut == NULL || pdu == NULL || pdu_len == 0u ||
        pdu_len > LOOPBACK_MAX_PDU_SIZE) {
        return -EINVAL;
    }
    if (ut->receive == NULL) {
        return -ENOTCONN;
    }

    ut->sent_count++;
    ut->last_dest_entity_id = dest_entity_id;

    if (ut->drop_first_octet_enabled && pdu[0] == ut->drop_first_octet) {
        ut->dropped_count++;
        return 0;
    }

    ut->delivered_count++;
    ut->receive(ut->receive_user, ut->local_entity_id, pdu, pdu_len);
    return 0;
}

static uint64_t loopback_now_ms(void *user)
{
    const struct loopback_ut *ut = user;

    if (ut == NULL) {
        return 0u;
    }

    return ut->now_ms;
}

static void capture_receive(void *user, uint64_t source_entity_id,
                            const uint8_t *pdu, size_t pdu_len)
{
    struct receive_capture *capture = user;

    zassert_not_null(capture);
    zassert_equal(user, capture->expected_user);
    zassert_not_null(pdu);
    zassert_true(pdu_len <= sizeof(capture->pdu));

    capture->called = true;
    capture->source_entity_id = source_entity_id;
    memcpy(capture->pdu, pdu, pdu_len);
    capture->pdu_len = pdu_len;
}

static void init_loopback(struct loopback_ut *ut,
                          ccsds_cfdp_ut_ops_t *ops,
                          struct receive_capture *capture)
{
    memset(ut, 0, sizeof(*ut));
    memset(capture, 0, sizeof(*capture));

    ut->local_entity_id = 42u;
    ut->now_ms = 123456u;
    ut->receive = capture_receive;
    ut->receive_user = capture;
    capture->expected_user = capture;

    *ops = (ccsds_cfdp_ut_ops_t){
        .user = ut,
        .send_pdu = loopback_send_pdu,
        .now_ms = loopback_now_ms,
    };
}

ZTEST(ccsds_cfdp_ut, test_send_invokes_registered_receiver)
{
    struct loopback_ut ut;
    ccsds_cfdp_ut_ops_t ops;
    struct receive_capture capture;
    const uint8_t pdu[] = { 0x07u, 0xAAu, 0x55u };

    init_loopback(&ut, &ops, &capture);

    zassert_equal(ops.send_pdu(ops.user, 99u, pdu, sizeof(pdu)), 0);

    zassert_true(capture.called);
    zassert_equal(capture.source_entity_id, ut.local_entity_id);
    zassert_equal(capture.pdu_len, sizeof(pdu));
    zassert_mem_equal(capture.pdu, pdu, sizeof(pdu));
    zassert_equal(ut.sent_count, 1u);
    zassert_equal(ut.delivered_count, 1u);
    zassert_equal(ut.dropped_count, 0u);
    zassert_equal(ut.last_dest_entity_id, 99u);
}

ZTEST(ccsds_cfdp_ut, test_user_pointers_are_propagated)
{
    struct loopback_ut ut;
    ccsds_cfdp_ut_ops_t ops;
    struct receive_capture capture;
    const uint8_t pdu[] = { 0x04u };

    init_loopback(&ut, &ops, &capture);

    zassert_equal(ops.user, &ut);
    zassert_equal(ut.receive_user, &capture);
    zassert_equal(ops.send_pdu(ops.user, 77u, pdu, sizeof(pdu)), 0);
    zassert_true(capture.called);
    zassert_equal(capture.expected_user, &capture);
}

ZTEST(ccsds_cfdp_ut, test_now_callback_uses_transport_user_pointer)
{
    struct loopback_ut ut;
    ccsds_cfdp_ut_ops_t ops;
    struct receive_capture capture;

    init_loopback(&ut, &ops, &capture);

    zassert_equal(ops.now_ms(ops.user), ut.now_ms);
}

ZTEST(ccsds_cfdp_ut, test_loopback_can_drop_selected_first_octet)
{
    struct loopback_ut ut;
    ccsds_cfdp_ut_ops_t ops;
    struct receive_capture capture;
    const uint8_t dropped_pdu[] = { 0xFDu, 0x01u };

    init_loopback(&ut, &ops, &capture);
    ut.drop_first_octet_enabled = true;
    ut.drop_first_octet = dropped_pdu[0];

    zassert_equal(ops.send_pdu(ops.user, 99u, dropped_pdu,
                               sizeof(dropped_pdu)), 0);

    zassert_false(capture.called);
    zassert_equal(ut.sent_count, 1u);
    zassert_equal(ut.delivered_count, 0u);
    zassert_equal(ut.dropped_count, 1u);
}

ZTEST(ccsds_cfdp_ut, test_invalid_loopback_inputs)
{
    struct loopback_ut ut;
    ccsds_cfdp_ut_ops_t ops;
    struct receive_capture capture;
    uint8_t pdu[LOOPBACK_MAX_PDU_SIZE + 1u] = { 0u };

    init_loopback(&ut, &ops, &capture);

    zassert_equal(ops.send_pdu(NULL, 99u, pdu, 1u), -EINVAL);
    zassert_equal(ops.send_pdu(ops.user, 99u, NULL, 1u), -EINVAL);
    zassert_equal(ops.send_pdu(ops.user, 99u, pdu, 0u), -EINVAL);
    zassert_equal(ops.send_pdu(ops.user, 99u, pdu, sizeof(pdu)), -EINVAL);

    ut.receive = NULL;
    zassert_equal(ops.send_pdu(ops.user, 99u, pdu, 1u), -ENOTCONN);
    zassert_equal(ops.now_ms(NULL), 0u);
}

ZTEST_SUITE(ccsds_cfdp_ut, NULL, NULL, NULL, NULL, NULL);
