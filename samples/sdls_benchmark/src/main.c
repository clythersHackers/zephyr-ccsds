#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#define BENCH_TAG_LEN 16u
#define BENCH_NONCE_LEN 12u
#define BENCH_AAD_LEN 18u
#define BENCH_MAX_PAYLOAD 1024u
#define BENCH_WARMUP_REPS 32u

static const uint8_t aad[BENCH_AAD_LEN] = {
    0x20, 0x01, 0x12, 0x34, 0x02, 0x01, 0x00, 0x00,
    0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
    0x02, 0x03,
};
static uint8_t plaintext[BENCH_MAX_PAYLOAD];
static uint8_t protected_data[BENCH_MAX_PAYLOAD + BENCH_TAG_LEN];
static uint8_t clear_data[BENCH_MAX_PAYLOAD];

struct bench_measurement {
    uint64_t elapsed_cycles;
    uint64_t busy_cycles;
    uint64_t elapsed_ns;
};

static void wipe_key(uint8_t *key, size_t len)
{
    volatile uint8_t *p = key;

    while (len-- > 0u) {
        *p++ = 0u;
    }
}

static void set_nonce(uint8_t nonce[BENCH_NONCE_LEN], uint32_t counter)
{
    static const uint8_t prefix[8] = {
        0x53, 0x44, 0x4c, 0x53, 0x42, 0x45, 0x4e, 0x43
    };

    memcpy(nonce, prefix, sizeof(prefix));
    nonce[8] = (uint8_t)(counter >> 24);
    nonce[9] = (uint8_t)(counter >> 16);
    nonce[10] = (uint8_t)(counter >> 8);
    nonce[11] = (uint8_t)counter;
}

static int encrypt_once(psa_key_id_t key_id, size_t payload_len,
                        uint32_t counter)
{
    uint8_t nonce[BENCH_NONCE_LEN];
    size_t output_len;
    psa_status_t status;

    set_nonce(nonce, counter);
    status = psa_aead_encrypt(
        key_id, PSA_ALG_GCM, nonce, sizeof(nonce), aad, sizeof(aad),
        payload_len == 0u ? NULL : plaintext, payload_len, protected_data,
        payload_len + BENCH_TAG_LEN, &output_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return output_len == payload_len + BENCH_TAG_LEN ? 0 : -1;
}

static int decrypt_once(psa_key_id_t key_id, size_t payload_len,
                        uint32_t counter)
{
    uint8_t nonce[BENCH_NONCE_LEN];
    size_t output_len;
    psa_status_t status;

    set_nonce(nonce, counter);
    status = psa_aead_decrypt(
        key_id, PSA_ALG_GCM, nonce, sizeof(nonce), aad, sizeof(aad),
        protected_data, payload_len + BENCH_TAG_LEN, clear_data,
        sizeof(clear_data), &output_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return output_len == payload_len ? 0 : -1;
}

static int run_batch(psa_key_id_t key_id, size_t payload_len, uint32_t reps,
                     bool encrypt, struct bench_measurement *measurement)
{
    k_thread_runtime_stats_t before;
    k_thread_runtime_stats_t after;
    uint64_t start;
    uint64_t end;
    int ret;

    if (!encrypt) {
        ret = encrypt_once(key_id, payload_len, 1u);
        if (ret != 0) {
            return ret;
        }
    }

    (void)k_thread_runtime_stats_get(k_current_get(), &before);
    start = k_cycle_get_64();
    for (uint32_t i = 0u; i < reps; i++) {
        ret = encrypt ? encrypt_once(key_id, payload_len, i + 1u)
                      : decrypt_once(key_id, payload_len, 1u);
        if (ret != 0) {
            return ret;
        }
    }
    end = k_cycle_get_64();
    (void)k_thread_runtime_stats_get(k_current_get(), &after);

    measurement->elapsed_cycles = end - start;
    measurement->elapsed_ns =
        k_cyc_to_ns_floor64(measurement->elapsed_cycles);
    measurement->busy_cycles =
        after.execution_cycles - before.execution_cycles;
    return 0;
}

static uint32_t repetitions_for(size_t payload_len)
{
    if (payload_len <= 64u) {
        return 2000u;
    }
    if (payload_len <= 256u) {
        return 1000u;
    }
    return 400u;
}

static int benchmark_case(psa_key_id_t key_id, size_t payload_len)
{
    const uint32_t reps = repetitions_for(payload_len);
    const uint64_t bytes_per_op =
        payload_len == 0u ? BENCH_AAD_LEN : payload_len;
    struct bench_measurement measurement;
    int ret;

    for (uint32_t i = 0u; i < BENCH_WARMUP_REPS; i++) {
        ret = encrypt_once(key_id, payload_len, 0x80000000u + i);
        if (ret != 0) {
            return ret;
        }
        ret = decrypt_once(key_id, payload_len, 0x80000000u + i);
        if (ret != 0) {
            return ret;
        }
    }

    for (unsigned int direction = 0u; direction < 2u; direction++) {
        const bool encrypt = direction == 0u;
        uint64_t throughput;
        uint64_t busy_permille;

        ret = run_batch(key_id, payload_len, reps, encrypt, &measurement);
        if (ret != 0) {
            return ret;
        }
        throughput = measurement.elapsed_ns == 0u
                         ? 0u
                         : bytes_per_op * reps * 1000000000ULL /
                               measurement.elapsed_ns;
        busy_permille = measurement.elapsed_cycles == 0u
                            ? 0u
                            : measurement.busy_cycles * 1000u /
                                  measurement.elapsed_cycles;
        printf("%s %-7s bytes=%4zu reps=%4" PRIu32
               " cycles=%" PRIu64 " ns=%" PRIu64
               " throughput_Bps=%" PRIu64
               " thread_busy_cycles=%" PRIu64 " busy_permille=%" PRIu64
               "\n",
               payload_len == 0u ? "GMAC" : "GCM ",
               encrypt ? "encrypt" : "decrypt", payload_len, reps,
               measurement.elapsed_cycles, measurement.elapsed_ns, throughput,
               measurement.busy_cycles, busy_permille);
    }

    return 0;
}

int main(void)
{
    static const size_t payload_sizes[] = { 0u, 32u, 64u, 256u, 1024u };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t plaintext_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    psa_status_t status;
    int ret = 0;

    for (size_t i = 0u; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)i;
    }

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("PSA init failed: %" PRId32 "\n", status);
        return 1;
    }

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256u);
    status = psa_import_key(&attributes, plaintext_key, sizeof(plaintext_key),
                            &key_id);
    wipe_key(plaintext_key, sizeof(plaintext_key));
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        printf("PSA key import failed: %" PRId32 "\n", status);
        return 1;
    }

    printf("CCSDS SDLS PSA AES-256-GCM benchmark\n");
    printf("warmup=%u AAD=%u; bytes=0 is GMAC-style AAD-only input\n",
           BENCH_WARMUP_REPS, BENCH_AAD_LEN);
    for (size_t i = 0u; i < ARRAY_SIZE(payload_sizes); i++) {
        ret = benchmark_case(key_id, payload_sizes[i]);
        if (ret != 0) {
            printf("benchmark failed at %zu bytes: %d\n", payload_sizes[i],
                   ret);
            break;
        }
    }

    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        printf("PSA key destroy failed: %" PRId32 "\n", status);
        ret = 1;
    }
    printf("benchmark complete\n");
    return ret == 0 ? 0 : 1;
}
