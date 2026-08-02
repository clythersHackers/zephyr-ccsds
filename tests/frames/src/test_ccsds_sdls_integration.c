#ifdef CONFIG_CCSDS_SDLS

#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include "ccsds/ccsds_bch.h"
#include "ccsds/ccsds_crc16.h"
#include "ccsds/ccsds_profile.h"
#include "ccsds/ccsds_sdls.h"
#include "ccsds/ccsds_tc_segment.h"
#include "ccsds/ccsds_tm_frame.h"

#define TEST_SPI 1u
#define TEST_KEY_ID CONFIG_CCSDS_SDLS_SESSION_KEY_BASE
#define TEST_TC_PRIMARY_HDR_LEN 5u
#define TEST_TM_ASM_LEN 4u
#define TEST_TM_PRIMARY_HDR_LEN 6u
#define TEST_TM_OCF_LEN 4u

#ifdef CONFIG_CCSDS_RS
#include "ccsds/ccsds_rs.h"
#define TEST_TM_FRAME_LEN CCSDS_RS_INTERLEAVED_DATA_LEN
#define TEST_TM_CODED_LEN                                                      \
    (TEST_TM_ASM_LEN + TEST_TM_FRAME_LEN + CCSDS_RS_INTERLEAVED_PARITY_LEN)
#else
#define TEST_TM_FRAME_LEN CONFIG_CCSDS_MAX_FRAME_LEN
#define TEST_TM_CODED_LEN (TEST_TM_ASM_LEN + TEST_TM_FRAME_LEN)
#endif

#ifdef CONFIG_CCSDS_TM_FECF
#define TEST_TM_FECF_LEN CCSDS_CRC16_LEN
#else
#define TEST_TM_FECF_LEN 0u
#endif

BUILD_ASSERT(TEST_TM_FRAME_LEN > TEST_TM_PRIMARY_HDR_LEN +
                                     CCSDS_SDLS_PROTECTED_OVERHEAD +
                                     TEST_TM_OCF_LEN + TEST_TM_FECF_LEN);

static psa_key_id_t good_key;
static psa_key_id_t wrong_key;

struct packet_capture {
    uint16_t apid;
    uint8_t count;
};

struct ep_service_capture {
    struct ccsds_sdls_ctx *sdls;
    uint8_t reply[CCSDS_SDLS_EP_REPLY_PDU_MAX];
    size_t reply_len;
    uint8_t calls;
};

static int integration_self_test(void *user_data, uint8_t *result)
{
    ARG_UNUSED(user_data);
    *result = CCSDS_SDLS_SELF_TEST_OK;
    return 0;
}

struct tm_capture {
    uint8_t frame[TEST_TM_CODED_LEN];
    size_t len;
    uint8_t calls;
};

bool ccsds_tm_frame_test_run_cycle(k_timeout_t *next_delay, uint8_t *vcid);

static psa_key_id_t import_key(uint8_t seed)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t bytes[CCSDS_SDLS_AES_KEY_BITS / 8u];

    for (size_t i = 0u; i < sizeof(bytes); i++) {
        bytes[i] = seed + (uint8_t)i;
    }

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, CCSDS_SDLS_AES_KEY_BITS);
    zassert_equal(psa_import_key(&attributes, bytes, sizeof(bytes), &key_id),
                  PSA_SUCCESS);
    memset(bytes, 0, sizeof(bytes));
    psa_reset_key_attributes(&attributes);

    return key_id;
}

static void init_ctx(struct ccsds_sdls_ctx *ctx, psa_key_id_t psa_key,
                     enum ccsds_sdls_sa_role role,
                     enum ccsds_sdls_security_mode mode,
                     enum ccsds_sdls_sa_state sa_state,
                     enum ccsds_sdls_key_state key_state, uint32_t rx_arsn,
                     bool rx_initialized)
{
    const struct ccsds_sdls_key_init key = {
        .psa_key_id = psa_key,
        .key_id = TEST_KEY_ID,
        .state = key_state,
    };
    const struct ccsds_sdls_sa_init sa = {
        .spi = TEST_SPI,
        .key_id = TEST_KEY_ID,
        .rx_arsn = rx_arsn,
        .role = role,
        .mode = mode,
        .state = sa_state,
        .has_key = true,
        .rx_arsn_initialized = rx_initialized,
    };

    ccsds_sdls_init(ctx, &sa, 1u, &key, 1u);
}

static void build_tc_primary_header(uint8_t *frame, size_t frame_len,
                                    uint8_t vcid, uint8_t fsn)
{
    uint16_t length = (uint16_t)(frame_len - 1u);

    frame[0] = (uint8_t)((CONFIG_CCSDS_SPACECRAFT_ID >> 8) & 0x03u);
    frame[1] = (uint8_t)CONFIG_CCSDS_SPACECRAFT_ID;
    frame[2] = (uint8_t)((vcid << 2) | ((length >> 8) & 0x03u));
    frame[3] = (uint8_t)length;
    frame[4] = fsn;
}

static size_t build_secured_tc_frame_data(struct ccsds_sdls_ctx *tx,
                                          const uint8_t *clear_data,
                                          size_t clear_data_len,
                                          uint8_t *frame,
                                          size_t frame_capacity)
{
    size_t frame_len = TEST_TC_PRIMARY_HDR_LEN + clear_data_len +
                       CCSDS_SDLS_PROTECTED_OVERHEAD;
    uint8_t scratch[128];
    struct ccsds_sdls_auth_header auth = {
        .data = frame,
        .mask = ccsds_sdls_tc_default_auth_mask,
        .len = TEST_TC_PRIMARY_HDR_LEN + CCSDS_TC_SEGMENT_HDR_LEN,
        .mask_len = CCSDS_SDLS_TC_DEFAULT_AUTH_MASK_LEN,
    };
    struct ccsds_sdls_workspace workspace = {
        .data = scratch,
        .capacity = sizeof(scratch),
    };

    zassert_true(frame_len <= frame_capacity);
    zassert_true(clear_data_len >= CCSDS_TC_SEGMENT_HDR_LEN);
    memset(frame, 0, frame_len);
    build_tc_primary_header(frame, frame_len, 0u, 0u);
    frame[TEST_TC_PRIMARY_HDR_LEN] = clear_data[0];
    zassert_ok(ccsds_sdls_apply_security(
        tx, CCSDS_SDLS_SA_EP_REPLY_TX, TEST_SPI, auth,
        clear_data + CCSDS_TC_SEGMENT_HDR_LEN,
        clear_data_len - CCSDS_TC_SEGMENT_HDR_LEN, workspace,
        &frame[TEST_TC_PRIMARY_HDR_LEN + CCSDS_TC_SEGMENT_HDR_LEN],
        frame_capacity - TEST_TC_PRIMARY_HDR_LEN -
            CCSDS_TC_SEGMENT_HDR_LEN));

    return frame_len;
}

static size_t build_secured_tc_frame(struct ccsds_sdls_ctx *tx, uint8_t *frame,
                                     size_t frame_capacity)
{
    static const uint8_t clear_data[] = {
        0xc0u, /* unsegmented TC Segment Header, MAP ID zero */
        0x10u, 0x2au, 0xc0u, 0x00u, 0x00u, 0x00u, 0xa5u,
    };

    return build_secured_tc_frame_data(tx, clear_data, sizeof(clear_data),
                                       frame, frame_capacity);
}

static size_t build_tc_control_frame(uint8_t *frame, size_t frame_capacity,
                                     bool bypass, const uint8_t *command,
                                     size_t command_len)
{
    size_t frame_len = TEST_TC_PRIMARY_HDR_LEN + command_len;

    zassert_true(command_len > 0u);
    zassert_true(frame_len <= frame_capacity);
    memset(frame, 0, frame_len);
    build_tc_primary_header(frame, frame_len, 0u, 0u);
    frame[0] |= 0x10u;
    if (bypass) {
        frame[0] |= 0x20u;
    }
    memcpy(frame + TEST_TC_PRIMARY_HDR_LEN, command, command_len);

    return frame_len;
}

static void encode_bch_block(const uint8_t data[CCSDS_BCH_DATA_SIZE],
                             uint8_t block[CCSDS_BCH_BLOCK_SIZE])
{
    uint8_t decoded[CCSDS_BCH_DATA_SIZE];
    int corrected_bit;

    memcpy(block, data, CCSDS_BCH_DATA_SIZE);
    for (uint16_t parity = 0u; parity <= UINT8_MAX; parity++) {
        block[CCSDS_BCH_DATA_SIZE] = (uint8_t)parity;
        if (ccsds_bch_decode_block(block, decoded, &corrected_bit) ==
                CCSDS_BCH_OK &&
            memcmp(decoded, data, CCSDS_BCH_DATA_SIZE) == 0) {
            return;
        }
    }
    zassert_unreachable("no BCH parity byte found");
}

static size_t encode_cltu(const uint8_t *frame, size_t frame_len, uint8_t *cltu,
                          size_t cltu_capacity)
{
    static const uint8_t tail[CCSDS_BCH_BLOCK_SIZE] = {
        0xc5u, 0xc5u, 0xc5u, 0xc5u, 0xc5u, 0xc5u, 0xc5u, 0x79u,
    };
    uint8_t data[CCSDS_BCH_DATA_SIZE];
    size_t blocks =
        (frame_len + CCSDS_BCH_DATA_SIZE - 1u) / CCSDS_BCH_DATA_SIZE;
    size_t cltu_len = 2u + blocks * CCSDS_BCH_BLOCK_SIZE + sizeof(tail);

    zassert_true(cltu_len <= cltu_capacity);
    cltu[0] = 0xebu;
    cltu[1] = 0x90u;
    for (size_t i = 0u; i < blocks; i++) {
        size_t offset = i * CCSDS_BCH_DATA_SIZE;
        size_t copy_len = MIN(frame_len - offset, sizeof(data));

        memset(data, 0x55, sizeof(data));
        memcpy(data, frame + offset, copy_len);
        encode_bch_block(data, cltu + 2u + i * CCSDS_BCH_BLOCK_SIZE);
    }
    memcpy(cltu + 2u + blocks * CCSDS_BCH_BLOCK_SIZE, tail, sizeof(tail));

    return cltu_len;
}

static int capture_packet(const struct ccsds_space_packet *packet,
                          void *user_data)
{
    struct packet_capture *capture = user_data;

    capture->apid = packet->apid;
    capture->count++;
    return 0;
}

static int process_ep_packet(const struct ccsds_space_packet *packet,
                             void *user_data)
{
    struct ep_service_capture *capture = user_data;
    struct ccsds_sdls_workspace workspace = {0};

    capture->calls++;
    return ccsds_sdls_ep_process_pdu(
        capture->sdls, packet->payload, packet->payload_len, workspace,
        capture->reply, sizeof(capture->reply), &capture->reply_len);
}

static void init_tc_profile(struct ccsds_profile_tc_rx *profile,
                            struct ccsds_router *router,
                            struct packet_capture *capture,
                            struct ccsds_sdls_ctx *rx, uint8_t vcid)
{
    ccsds_router_init(router);
    zassert_ok(
        ccsds_router_register_apid(router, 0x2au, capture_packet, capture));
    ccsds_profile_tc_rx_init(profile, router);
    zassert_ok(ccsds_profile_tc_set_accepted_vcid(profile, vcid));
    ccsds_profile_tc_rx_set_sdls(profile, rx);
}

static void expect_tc_reject(uint8_t *frame, size_t frame_len,
                             struct ccsds_sdls_ctx *rx, uint8_t vcid,
                             int expected_error)
{
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_tc_vc_state vc_before;
    struct ccsds_profile_tc_reassembly reassembly_before;
    struct ccsds_router router;
    struct packet_capture capture = {0};
    uint8_t cltu[CONFIG_CCSDS_MAX_CLTU_LEN];
    size_t cltu_len;
    uint32_t arsn_before = rx->sas[TEST_SPI - 1u].rx_arsn;
    bool initialized_before = rx->sas[TEST_SPI - 1u].rx_arsn_initialized;

    init_tc_profile(&profile, &router, &capture, rx, vcid);
    vc_before = profile.vc_state;
    reassembly_before = profile.reassembly;
    cltu_len = encode_cltu(frame, frame_len, cltu, sizeof(cltu));

    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  expected_error);
    zassert_mem_equal(&profile.vc_state, &vc_before, sizeof(vc_before));
    zassert_mem_equal(&profile.reassembly, &reassembly_before,
                      sizeof(reassembly_before));
    zassert_equal(capture.count, 0u);
    zassert_equal(rx->sas[TEST_SPI - 1u].rx_arsn, arsn_before);
    zassert_equal(rx->sas[TEST_SPI - 1u].rx_arsn_initialized,
                  initialized_before);
}

ZTEST(ccsds_sdls_integration, test_secured_tc_gmac_delivery_and_rejections)
{
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_tc_vc_state vc_before;
    struct ccsds_profile_tc_reassembly reassembly_before;
    struct ccsds_router router;
    struct packet_capture capture = {0};
    uint8_t original[96];
    uint8_t frame[96];
    uint8_t cltu[CONFIG_CCSDS_MAX_CLTU_LEN];
    size_t frame_len;
    size_t cltu_len;

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_EP_REPLY_TX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    frame_len = build_secured_tc_frame(&tx, original, sizeof(original));

    init_ctx(&rx, good_key, CCSDS_SDLS_SA_EP_COMMAND_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    init_tc_profile(&profile, &router, &capture, &rx, 0u);
    cltu_len = encode_cltu(original, frame_len, cltu, sizeof(cltu));
    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
    zassert_equal(capture.count, 1u);
    zassert_equal(capture.apid, 0x2au);
    zassert_equal(profile.vc_state.report_value, 1u);
    zassert_equal(profile.vc_state.farm_b_counter, 1u);

    vc_before = profile.vc_state;
    reassembly_before = profile.reassembly;
    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  CCSDS_SDLS_ERR_REPLAY);
    zassert_mem_equal(&profile.vc_state, &vc_before, sizeof(vc_before));
    zassert_mem_equal(&profile.reassembly, &reassembly_before,
                      sizeof(reassembly_before));
    zassert_equal(capture.count, 1u);

    memcpy(frame, original, frame_len);
    frame[2] ^= 0x04u;
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 1u, CCSDS_SDLS_ERR_AUTHENTICATION);

    memcpy(frame, original, frame_len);
    frame[TEST_TC_PRIMARY_HDR_LEN] ^= 0x01u;
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u,
                     CCSDS_SDLS_ERR_AUTHENTICATION);

    memcpy(frame, original, frame_len);
    frame[TEST_TC_PRIMARY_HDR_LEN + CCSDS_TC_SEGMENT_HDR_LEN +
          CCSDS_SDLS_SECURITY_HEADER_LEN + 1u] ^=
        0x01u;
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_AUTHENTICATION);

    memcpy(frame, original, frame_len);
    frame[frame_len - 1u] ^= 0x01u;
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_AUTHENTICATION);

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_EP_REPLY_TX, CCSDS_SDLS_MODE_GMAC,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    tx.keys[TEST_KEY_ID].tx_arsn = CONFIG_CCSDS_SDLS_ARSN_WINDOW + 1u;
    frame_len = build_secured_tc_frame(&tx, frame, sizeof(frame));
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, true);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_REPLAY);

    memcpy(frame, original, frame_len);
    sys_put_be16(2u, frame + TEST_TC_PRIMARY_HDR_LEN +
                         CCSDS_TC_SEGMENT_HDR_LEN);
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_UNKNOWN_SA);

    memcpy(frame, original, frame_len);
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_DEACTIVATED, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_KEY);

    init_ctx(&rx, wrong_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_AUTHENTICATION);

    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_STOPPED, CCSDS_SDLS_KEY_ACTIVE,
             0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_SA_STATE);
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_EXPIRED, CCSDS_SDLS_KEY_ACTIVE,
             0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_SA_STATE);

    memset(frame, 0,
           TEST_TC_PRIMARY_HDR_LEN + CCSDS_SDLS_PROTECTED_OVERHEAD - 1u);
    frame_len = TEST_TC_PRIMARY_HDR_LEN + CCSDS_SDLS_PROTECTED_OVERHEAD - 1u;
    build_tc_primary_header(frame, frame_len, 0u, 0u);
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    expect_tc_reject(frame, frame_len, &rx, 0u, CCSDS_SDLS_ERR_FORMAT);
}

ZTEST(ccsds_sdls_integration, test_secured_tc_gcm_keeps_segment_header_clear)
{
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_router router;
    struct packet_capture capture = {0};
    uint8_t frame[96];
    uint8_t cltu[CONFIG_CCSDS_MAX_CLTU_LEN];
    size_t frame_len;
    size_t cltu_len;

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
             CCSDS_SDLS_MODE_GCM, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    frame_len = build_secured_tc_frame(&tx, frame, sizeof(frame));

    zassert_equal(frame[TEST_TC_PRIMARY_HDR_LEN], 0xc0u);
    zassert_equal(sys_get_be16(frame + TEST_TC_PRIMARY_HDR_LEN +
                              CCSDS_TC_SEGMENT_HDR_LEN),
                  TEST_SPI);

    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GCM, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    init_tc_profile(&profile, &router, &capture, &rx, 0u);
    cltu_len = encode_cltu(frame, frame_len, cltu, sizeof(cltu));
    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
    zassert_equal(capture.count, 1u);
    zassert_equal(capture.apid, 0x2au);
}

ZTEST(ccsds_sdls_integration, test_ep_is_packet_service_after_frame_security)
{
    enum {
        EP_MAP_ID = 63u,
        EP_APID = 1u,
        TARGET_SPI = 2u,
    };
    const struct ccsds_sdls_key_init key = {
        .psa_key_id = good_key,
        .key_id = TEST_KEY_ID,
        .state = CCSDS_SDLS_KEY_ACTIVE,
    };
    const struct ccsds_sdls_sa_init rx_sas[] = {
        {.spi = TEST_SPI,
         .key_id = TEST_KEY_ID,
         .role = CCSDS_SDLS_SA_EP_COMMAND_RX,
         .mode = CCSDS_SDLS_MODE_GMAC,
         .state = CCSDS_SDLS_SA_OPERATIONAL,
         .has_key = true},
        {.spi = TARGET_SPI,
         .key_id = TEST_KEY_ID,
         .role = CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
         .mode = CCSDS_SDLS_MODE_GMAC,
         .state = CCSDS_SDLS_SA_STOPPED,
         .has_key = true},
    };
    struct ccsds_sdls_ep_set_arsn_window command = {
        .spi = TARGET_SPI,
        .window = 7u,
    };
    struct ccsds_space_packet packet = {
        .version = 0u,
        .type = CCSDS_PACKET_TYPE_TC,
        .secondary_header = false,
        .apid = EP_APID,
        .sequence_flags = CCSDS_SEQUENCE_UNSEGMENTED,
        .sequence_count = 0u,
    };
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_router router;
    struct ep_service_capture capture = {.sdls = &rx};
    uint8_t ep_pdu[CCSDS_SDLS_EP_HEADER_LEN + 6u];
    uint8_t encoded_packet[64];
    uint8_t clear_data[1u + sizeof(encoded_packet)];
    uint8_t frame[128];
    uint8_t cltu[CONFIG_CCSDS_MAX_CLTU_LEN];
    size_t packet_len;
    size_t frame_len;
    size_t cltu_len;

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    ccsds_sdls_init(&rx, rx_sas, ARRAY_SIZE(rx_sas), &key, 1u);
    ccsds_sdls_ep_set_arsn_window_encode(&command, ep_pdu, sizeof(ep_pdu));
    packet.payload = ep_pdu;
    packet.payload_len = sizeof(ep_pdu);
    zassert_ok(ccsds_space_packet_encode(&packet, encoded_packet,
                                         sizeof(encoded_packet), &packet_len));
    clear_data[0] = 0xc0u | EP_MAP_ID;
    memcpy(clear_data + 1u, encoded_packet, packet_len);
    frame_len = build_secured_tc_frame_data(
        &tx, clear_data, packet_len + 1u, frame, sizeof(frame));
    cltu_len = encode_cltu(frame, frame_len, cltu, sizeof(cltu));

    ccsds_router_init(&router);
    ccsds_profile_tc_rx_init(&profile, &router);
    ccsds_profile_tc_rx_set_sdls(&profile, &rx);
    zassert_ok(ccsds_profile_tc_set_map_apid_handler(
        &profile, EP_MAP_ID, EP_APID, process_ep_packet, &capture));

    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
    zassert_equal(capture.calls, 1u);
    zassert_equal(rx.sas[TARGET_SPI - 1u].rx_window, command.window);
    zassert_equal(rx.fsr.last_spi, TEST_SPI);
    zassert_equal(rx.fsr.last_arsn_lsb, 0u);
}

ZTEST(ccsds_sdls_integration, test_monitoring_pdus_use_authenticated_packet_route)
{
    enum {
        EP_MAP_ID = 63u,
        EP_APID = 1u,
    };
    struct ccsds_space_packet packet = {
        .version = 0u,
        .type = CCSDS_PACKET_TYPE_TC,
        .secondary_header = false,
        .apid = EP_APID,
        .sequence_flags = CCSDS_SEQUENCE_UNSEGMENTED,
    };
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_router router;
    struct ep_service_capture capture = {.sdls = &rx};
    uint8_t ep_pdu[CCSDS_SDLS_EP_HEADER_LEN];
    uint8_t encoded_packet[32];
    uint8_t clear_data[1u + sizeof(encoded_packet)];
    uint8_t frame[96];
    uint8_t cltu[CONFIG_CCSDS_MAX_CLTU_LEN];
    size_t packet_len;
    size_t frame_len;
    size_t cltu_len;

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_EP_REPLY_TX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    init_ctx(&rx, good_key, CCSDS_SDLS_SA_EP_COMMAND_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    ccsds_sdls_set_self_test(&rx, integration_self_test, NULL);
    ccsds_sdls_event_record(&rx, 0x31u, CCSDS_SDLS_EVENT_FORMAT, TEST_SPI,
                            0x01020304u);

    for (uint8_t procedure = CCSDS_SDLS_EP_PING;
         procedure <= CCSDS_SDLS_EP_SELF_TEST; procedure++) {
        ccsds_sdls_ep_monitoring_command_encode(
            (enum ccsds_sdls_ep_monitoring_procedure)procedure, ep_pdu,
            sizeof(ep_pdu));
        packet.sequence_count = procedure;
        packet.payload = ep_pdu;
        packet.payload_len = sizeof(ep_pdu);
        zassert_ok(ccsds_space_packet_encode(
            &packet, encoded_packet, sizeof(encoded_packet), &packet_len));
        clear_data[0] = 0xc0u | EP_MAP_ID;
        memcpy(clear_data + 1u, encoded_packet, packet_len);
        frame_len = build_secured_tc_frame_data(
            &tx, clear_data, packet_len + 1u, frame, sizeof(frame));
        cltu_len = encode_cltu(frame, frame_len, cltu, sizeof(cltu));

        ccsds_router_init(&router);
        ccsds_profile_tc_rx_init(&profile, &router);
        ccsds_profile_tc_rx_set_sdls(&profile, &rx);
        zassert_ok(ccsds_profile_tc_set_map_apid_handler(
            &profile, EP_MAP_ID, EP_APID, process_ep_packet, &capture));
        zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
        zassert_equal(capture.calls, procedure);
        zassert_equal(capture.reply[0], 0x80u | ep_pdu[0]);
        zassert_false(rx.authenticated_rx_valid);
    }
    zassert_equal(rx.event_count, 0u);
}

ZTEST(ccsds_sdls_integration, test_tc_type_bc_controls_bypass_sdls)
{
    static const uint8_t unlock[] = {0x00u};
    static const uint8_t set_vr[] = {0x82u, 0x00u, 0x2au};
    struct ccsds_sdls_ctx rx;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_router router;
    struct packet_capture capture = {0};
    uint8_t frame[TEST_TC_PRIMARY_HDR_LEN + sizeof(set_vr)];
    uint8_t cltu[CONFIG_CCSDS_MAX_CLTU_LEN];
    size_t frame_len;
    size_t cltu_len;

    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 7u, true);
    init_tc_profile(&profile, &router, &capture, &rx, 0u);
    profile.vc_state.lockout_flag = true;
    profile.vc_state.retransmit_flag = true;

    frame_len = build_tc_control_frame(frame, sizeof(frame), true, unlock,
                                       sizeof(unlock));
    cltu_len = encode_cltu(frame, frame_len, cltu, sizeof(cltu));
    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
    zassert_false(profile.vc_state.lockout_flag);
    zassert_false(profile.vc_state.retransmit_flag);
    zassert_equal(profile.vc_state.farm_b_counter, 1u);
    zassert_equal(rx.sas[TEST_SPI - 1u].rx_arsn, 7u);
    zassert_true(rx.sas[TEST_SPI - 1u].rx_arsn_initialized);
    zassert_equal(capture.count, 0u);

    profile.vc_state.retransmit_flag = true;
    frame_len = build_tc_control_frame(frame, sizeof(frame), true, set_vr,
                                       sizeof(set_vr));
    cltu_len = encode_cltu(frame, frame_len, cltu, sizeof(cltu));
    zassert_ok(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len));
    zassert_equal(profile.vc_state.report_value, 0x2au);
    zassert_false(profile.vc_state.retransmit_flag);
    zassert_equal(profile.vc_state.farm_b_counter, 2u);
    zassert_equal(rx.sas[TEST_SPI - 1u].rx_arsn, 7u);
    zassert_true(rx.sas[TEST_SPI - 1u].rx_arsn_initialized);
    zassert_equal(capture.count, 0u);
}

ZTEST(ccsds_sdls_integration, test_tc_reserved_control_type_is_rejected)
{
    static const uint8_t unlock[] = {0x00u};
    struct ccsds_sdls_ctx rx;
    struct ccsds_profile_tc_rx profile;
    struct ccsds_profile_tc_vc_state vc_before;
    struct ccsds_router router;
    struct packet_capture capture = {0};
    uint8_t frame[TEST_TC_PRIMARY_HDR_LEN + sizeof(unlock)];
    uint8_t cltu[CONFIG_CCSDS_MAX_CLTU_LEN];
    size_t frame_len;
    size_t cltu_len;

    init_ctx(&rx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TC_RX,
             CCSDS_SDLS_MODE_GMAC, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 7u, true);
    init_tc_profile(&profile, &router, &capture, &rx, 0u);
    profile.vc_state.lockout_flag = true;
    profile.vc_state.retransmit_flag = true;
    vc_before = profile.vc_state;

    frame_len = build_tc_control_frame(frame, sizeof(frame), false, unlock,
                                       sizeof(unlock));
    cltu_len = encode_cltu(frame, frame_len, cltu, sizeof(cltu));
    zassert_equal(ccsds_profile_tc_cltu_dispatch(&profile, cltu, cltu_len),
                  -EINVAL);
    zassert_mem_equal(&profile.vc_state, &vc_before, sizeof(vc_before));
    zassert_equal(rx.sas[TEST_SPI - 1u].rx_arsn, 7u);
    zassert_true(rx.sas[TEST_SPI - 1u].rx_arsn_initialized);
    zassert_equal(capture.count, 0u);
}

static int capture_tm(uint8_t vcid, const uint8_t *frame, size_t frame_len,
                      void *user_data)
{
    struct tm_capture *capture = user_data;

    ARG_UNUSED(vcid);
    zassert_true(frame_len <= sizeof(capture->frame));
    memcpy(capture->frame, frame, frame_len);
    capture->len = frame_len;
    capture->calls++;
    return 0;
}

static int fixed_clcw_provider(uint32_t *clcw, void *user_data)
{
    ARG_UNUSED(user_data);
    *clcw = 0x010ffffau;
    return 0;
}

static int process_tm(struct ccsds_sdls_ctx *rx, uint8_t *tm_frame,
                      uint8_t *clear)
{
    size_t protected_len = TEST_TM_FRAME_LEN - TEST_TM_PRIMARY_HDR_LEN -
                           TEST_TM_OCF_LEN - TEST_TM_FECF_LEN;
    uint8_t workspace_data[CONFIG_CCSDS_MAX_FRAME_LEN];
    struct ccsds_sdls_auth_header auth = {
        .data = tm_frame,
        .mask = ccsds_sdls_tm_default_auth_mask,
        .len = TEST_TM_PRIMARY_HDR_LEN,
        .mask_len = CCSDS_SDLS_TM_DEFAULT_AUTH_MASK_LEN,
    };
    struct ccsds_sdls_workspace workspace = {
        .data = workspace_data,
        .capacity = sizeof(workspace_data),
    };

    return ccsds_sdls_process_security(rx, CCSDS_SDLS_SA_EP_COMMAND_RX, auth,
                                       tm_frame + TEST_TM_PRIMARY_HDR_LEN,
                                       protected_len, workspace, clear,
                                       TEST_TM_FRAME_LEN);
}

static void init_tm_rx(struct ccsds_sdls_ctx *rx, psa_key_id_t key)
{
    init_ctx(rx, key, CCSDS_SDLS_SA_EP_COMMAND_RX, CCSDS_SDLS_MODE_GCM,
             CCSDS_SDLS_SA_OPERATIONAL, CCSDS_SDLS_KEY_ACTIVE, 0u, false);
}

ZTEST(ccsds_sdls_integration, test_secured_tm_gcm_round_trip_and_tampering)
{
    static const uint8_t packet[] = {
        0x08u, 0x2au, 0xc0u, 0x00u, 0x00u, 0x00u, 0xa5u,
    };
    const uint64_t sender_iv = UINT64_C(0x0123456789abcdef);
    const uint32_t arsn = UINT32_C(0x89abcdef);
    struct ccsds_sdls_ctx tx;
    struct ccsds_sdls_ctx rx;
    struct tm_capture capture = {0};
    uint8_t clear[CONFIG_CCSDS_MAX_FRAME_LEN];
    uint8_t tampered[TEST_TM_FRAME_LEN];
    uint8_t *tm_frame;
    uint8_t *security_header;

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
             CCSDS_SDLS_MODE_GCM, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    tx.tx_iv = sender_iv;
    tx.keys[TEST_KEY_ID].tx_arsn = arsn;

    ccsds_tm_frame_init();
    ccsds_tm_frame_set_sdls(&tx, TEST_SPI);
    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE, capture_tm,
                                             &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(0u, CCSDS_TM_ROUTE_ARCHIVE));
    zassert_ok(ccsds_tm_frame_add(0u, packet, sizeof(packet), K_NO_WAIT));
    zassert_true(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    zassert_equal(capture.calls, 1u);
    zassert_equal(capture.len, TEST_TM_CODED_LEN);

    tm_frame = capture.frame + TEST_TM_ASM_LEN;
    security_header = tm_frame + TEST_TM_PRIMARY_HDR_LEN;
    zassert_equal(sys_get_be16(security_header), TEST_SPI);
    zassert_equal(sys_get_be64(security_header + 2u), sender_iv);
    zassert_equal(sys_get_be32(security_header + 10u), arsn);
#ifdef CONFIG_CCSDS_TM_FECF
    zassert_true(ccsds_crc16_check(tm_frame, TEST_TM_FRAME_LEN));
#endif

    init_tm_rx(&rx, good_key);
    zassert_ok(process_tm(&rx, tm_frame, clear));
    zassert_mem_equal(clear, packet, sizeof(packet));

    memcpy(tampered, tm_frame, sizeof(tampered));
    tampered[0] ^= 0x01u;
    init_tm_rx(&rx, good_key);
    zassert_equal(process_tm(&rx, tampered, clear),
                  CCSDS_SDLS_ERR_AUTHENTICATION);

    memcpy(tampered, tm_frame, sizeof(tampered));
    tampered[TEST_TM_PRIMARY_HDR_LEN + CCSDS_SDLS_SECURITY_HEADER_LEN] ^= 0x01u;
    init_tm_rx(&rx, good_key);
    zassert_equal(process_tm(&rx, tampered, clear),
                  CCSDS_SDLS_ERR_AUTHENTICATION);

    memcpy(tampered, tm_frame, sizeof(tampered));
    tampered[TEST_TM_PRIMARY_HDR_LEN + 2u] ^= 0x01u;
    init_tm_rx(&rx, good_key);
    zassert_equal(process_tm(&rx, tampered, clear),
                  CCSDS_SDLS_ERR_AUTHENTICATION);

    memcpy(tampered, tm_frame, sizeof(tampered));
    tampered[TEST_TM_FRAME_LEN - TEST_TM_OCF_LEN - TEST_TM_FECF_LEN - 1u] ^=
        0x01u;
    init_tm_rx(&rx, good_key);
    zassert_equal(process_tm(&rx, tampered, clear),
                  CCSDS_SDLS_ERR_AUTHENTICATION);

    init_tm_rx(&rx, wrong_key);
    zassert_equal(process_tm(&rx, tm_frame, clear),
                  CCSDS_SDLS_ERR_AUTHENTICATION);
}

ZTEST(ccsds_sdls_integration, test_fsr_and_clcw_alternate_on_completed_frames)
{
    struct ccsds_sdls_ctx tx;
    struct tm_capture capture = {0};
    uint8_t observed[4][TEST_TM_OCF_LEN];
    const size_t ocf_offset = TEST_TM_ASM_LEN + TEST_TM_FRAME_LEN -
                              TEST_TM_FECF_LEN - TEST_TM_OCF_LEN;
    static const uint8_t clcw[] = {0x01u, 0x0fu, 0xffu, 0xfau};
    static const uint8_t fsr[] = {0x4au, 0x12u, 0x34u, 0x78u};

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
             CCSDS_SDLS_MODE_GCM, CCSDS_SDLS_SA_OPERATIONAL,
             CCSDS_SDLS_KEY_ACTIVE, 0u, false);
    tx.fsr.alarm = true;
    tx.fsr.bad_mac = true;
    tx.fsr.last_spi = 0x1234u;
    tx.fsr.last_arsn_lsb = 0x78u;
    ccsds_sdls_fsr_set_enabled(&tx, true);

    ccsds_tm_frame_init();
    ccsds_tm_frame_set_sdls(&tx, TEST_SPI);
    ccsds_tm_frame_set_clcw_provider(fixed_clcw_provider, NULL);
    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE, capture_tm,
                                             &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(7u, CCSDS_TM_ROUTE_ARCHIVE));

    for (size_t i = 0u; i < ARRAY_SIZE(observed); i++) {
        zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));
        memcpy(observed[i], capture.frame + ocf_offset, TEST_TM_OCF_LEN);
    }
    zassert_mem_equal(observed[0], clcw, sizeof(clcw));
    zassert_mem_equal(observed[1], fsr, sizeof(fsr));
    zassert_mem_equal(observed[2], clcw, sizeof(clcw));
    zassert_mem_equal(observed[3], fsr, sizeof(fsr));
    zassert_false(tx.fsr_next);
}

ZTEST(ccsds_sdls_integration, test_failed_tm_security_does_not_advance_ocf)
{
    struct ccsds_sdls_ctx tx;
    struct tm_capture capture = {0};
    const size_t ocf_offset = TEST_TM_ASM_LEN + TEST_TM_FRAME_LEN -
                              TEST_TM_FECF_LEN - TEST_TM_OCF_LEN;
    static const uint8_t clcw[] = {0x01u, 0x0fu, 0xffu, 0xfau};

    init_ctx(&tx, good_key, CCSDS_SDLS_SA_OPERATIONAL_TM_TX,
             CCSDS_SDLS_MODE_GCM, CCSDS_SDLS_SA_STOPPED, CCSDS_SDLS_KEY_ACTIVE,
             0u, false);
    ccsds_sdls_fsr_set_enabled(&tx, true);
    ccsds_tm_frame_init();
    ccsds_tm_frame_set_sdls(&tx, TEST_SPI);
    ccsds_tm_frame_set_clcw_provider(fixed_clcw_provider, NULL);
    zassert_ok(ccsds_tm_frame_register_route(CCSDS_TM_ROUTE_ARCHIVE, capture_tm,
                                             &capture));
    zassert_ok(ccsds_tm_frame_set_vc_route(7u, CCSDS_TM_ROUTE_ARCHIVE));

    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    zassert_equal(capture.calls, 0u);
    zassert_false(tx.fsr_next);

    tx.sas[TEST_SPI - 1u].state = CCSDS_SDLS_SA_OPERATIONAL;
    zassert_false(ccsds_tm_frame_test_run_cycle(NULL, NULL));
    zassert_equal(capture.calls, 1u);
    zassert_mem_equal(capture.frame + ocf_offset, clcw, sizeof(clcw));
    zassert_true(tx.fsr_next);
}

static void *integration_setup(void)
{
    zassert_equal(psa_crypto_init(), PSA_SUCCESS);
    good_key = import_key(0u);
    wrong_key = import_key(0x80u);
    return NULL;
}

static void integration_after(void *fixture)
{
    ARG_UNUSED(fixture);
    zassert_equal(psa_destroy_key(good_key), PSA_SUCCESS);
    zassert_equal(psa_destroy_key(wrong_key), PSA_SUCCESS);
}

ZTEST_SUITE(ccsds_sdls_integration, NULL, integration_setup, NULL, NULL,
            integration_after);

#endif /* CONFIG_CCSDS_SDLS */
