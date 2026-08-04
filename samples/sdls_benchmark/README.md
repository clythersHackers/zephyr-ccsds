# CCSDS SDLS PSA Benchmark

This application benchmarks the same PSA AES-256-GCM API used by the SDLS
proof. It measures authentication-only GMAC construction (zero plaintext and
18 bytes of AAD) and GCM payloads of 32, 64, 256, and 1024 bytes. Each case
warms up before timing encryption/tag generation and authenticated decryption.

The output reports elapsed hardware cycles, nanoseconds, payload (or GMAC AAD)
throughput, and current-thread execution cycles. The latter excludes time that
the thread is descheduled while an interrupt-assisted provider waits, where
the target's runtime-statistics implementation can measure that distinction.

Build the ESP32-S3 hardware-AES-driver-enabled variant from the west workspace
root:

```sh
west build -p always -b akiraconsole/esp32s3/procpu \
  modules/lib/ccsds/samples/sdls_benchmark \
  -d build-sdls-benchmark-hw \
  -- -DBOARD_ROOT="$PWD/AkiraOS" \
  -DEXTRA_CONF_FILE=overlay-hw.conf
```

Build the hardware-driver-disabled Mbed TLS software variant:

```sh
west build -p always -b akiraconsole/esp32s3/procpu \
  modules/lib/ccsds/samples/sdls_benchmark \
  -d build-sdls-benchmark-sw \
  -- -DBOARD_ROOT="$PWD/AkiraOS" \
  -DEXTRA_CONF_FILE=overlay-sw.conf
```

Connect the board's native USB port, then flash and attach a serial monitor:

```sh
west flash -d build-sdls-benchmark-hw
west espressif monitor -d build-sdls-benchmark-hw
```

Repeat with `build-sdls-benchmark-sw`. If the monitor runner is unavailable,
open the board's configured UART at 115200 baud after `west flash`. Keep the
complete logs and compare like-for-like rows. The ESP32 Zephyr Crypto driver
does not by itself establish that PSA GCM uses it; inspect the linked symbols
and compare measurements before describing a row as accelerated.
