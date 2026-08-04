# SDLS Stage 1 proof record

This note records the fixed-state and PSA provider evidence for the Stage 1
implementation. It is a design/verification record, not a claim that SDLS
transfer-frame processing is implemented.

## Fixed state

`struct ccsds_sdls_ctx` embeds all configured SA and key slots. With the
default `CONFIG_CCSDS_SDLS_MAX_SA=4` and
`CONFIG_CCSDS_SDLS_MAX_KEYS=8`, with session keys beginning at Key ID 4,
compile-time checks on both native and
ESP32-S3 builds establish this layout:

| Component | Count | Bytes each | Bytes |
|---|---:|---:|---:|
| Mutable SA state | 4 | 8 | 32 |
| Key metadata and transmit counter | 8 | 12 | 96 |
| SA role and mode arrays | — | — | 8 |
| Sender IV state | 1 | 8 | 8 |
| Total caller-owned context | — | — | 144 |

The context has no pointers to allocated tables and no operational key-byte
arrays. PSA key storage and the PSA provider's own resources are outside this
144-byte protocol-state cost.

## PSA proof

The focused test imports volatile AES-256 keys through PSA, wipes each
plaintext import buffer immediately, and destroys each key during test
cleanup. It covers:

- NIST AES-256-GCM known-answer encryption and authenticated decryption;
- authentication failure after changing the tag;
- the NIST GCMVS AES-256 zero-plaintext, AAD-only construction used as GMAC;
- GMAC tag verification and modified-tag rejection; and
- fixed-state initialization, direct lookup, duplicate slots, unknown IDs, and
  capacity exhaustion.

Run from the west workspace root:

```sh
west twister -T modules/lib/ccsds/tests/sdls -p native_sim \
  --inline-logs --outdir /tmp/ccsds-twister-sdls-stage1

west build -p always -b akiraconsole/esp32s3/procpu \
  modules/lib/ccsds/tests/sdls \
  -d /tmp/ccsds-sdls-proof-esp32s3 \
  -- -DBOARD_ROOT="$PWD/AkiraOS"
```

## Resolved ESP32-S3 provider

The resolved proof and benchmark configurations select
`PSA_WANT_ALG_GCM`, `PSA_WANT_KEY_TYPE_AES`,
`MBEDTLS_PSA_CRYPTO_C`, and the Mbed TLS AES/GCM implementation.
The ELF symbols and build graph establish this selected chain:

```text
psa_aead_encrypt/decrypt
-> Mbed TLS PSA driver wrapper
-> mbedtls_psa_aead_encrypt/decrypt
-> mbedtls_gcm_crypt_and_tag/auth_decrypt
-> Mbed TLS software gcm.c and aes.c
```

No `esp_aes_gcm_*` symbol or Espressif Mbed TLS GCM alternative source is
present in either linked benchmark. Enabling Zephyr's
`CONFIG_CRYPTO_ESP32_AES` compiles the ESP32 AES engine driver and
`aes_hal_*`, but that driver serves Zephyr's Crypto API and supports ECB, CBC,
and CTR. The Mbed TLS PSA driver wrapper does not register it as a PSA AEAD
accelerator. Therefore the Stage 1 PSA GCM and GMAC operations are software in
both benchmark variants; the hardware-enabled variant must not be described
as accelerated.

For the resolved hardware-driver-enabled variant:

- hardware AES engine driver: enabled;
- PSA use of the hardware AES engine: not selected;
- DMA or interrupt operation for PSA GCM: not selected;
- full hardware GCM: not selected;
- GHASH: Mbed TLS software `gcm.c`.

The checked-in Espressif provider contains a separate `esp_aes_gcm_*`
alternative, but this Zephyr build does not integrate it. That source has a
conditional DMA GCM path and an interrupt threshold above 2000 bytes. Its
partial path computes GHASH in software, and it explicitly sends zero-length
payloads (the GMAC case) to the partial path. The ESP32-S3 capability files in
this workspace do not enable `SOC_AES_SUPPORT_GCM`, so this source does not
establish a full-hardware GCM path for the current target even independently
of the missing Zephyr integration.

## Benchmark

The isolated benchmark uses only PSA AEAD calls. It covers AAD-only GMAC and
32, 64, 256, and 1024-byte GCM payloads, with 32 warm-up operations before
timed batches. It reports elapsed cycles, time, bytes per second, current
thread execution cycles, and a busy-time ratio.

Build both variants:

```sh
west build -p always -b akiraconsole/esp32s3/procpu \
  modules/lib/ccsds/samples/sdls_benchmark \
  -d /tmp/ccsds-sdls-benchmark-hw \
  -- -DBOARD_ROOT="$PWD/AkiraOS" \
  -DEXTRA_CONF_FILE=overlay-hw.conf

west build -p always -b akiraconsole/esp32s3/procpu \
  modules/lib/ccsds/samples/sdls_benchmark \
  -d /tmp/ccsds-sdls-benchmark-sw \
  -- -DBOARD_ROOT="$PWD/AkiraOS" \
  -DEXTRA_CONF_FILE=overlay-sw.conf
```

No serial device was available in the development container during this
proof, so no performance values are recorded. Flash, monitor, and comparison
instructions are in `samples/sdls_benchmark/README.md`.

## Stage 1 boundaries

This stage does not implement security headers/trailers, frame processing,
Extended Procedures, OTAR, replay decisions, IV allocation or persistence, or
runtime algorithm selection. It proves only fixed metadata/state ownership and
the PSA AES-256-GCM/GMAC primitive boundary. Resolving a PSA-to-Espressif GCM
accelerator integration remains a provider/integration task; it is not hidden
behind the reusable SDLS API.
