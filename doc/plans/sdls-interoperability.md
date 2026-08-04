# SDLS interoperability plan

## Status

The fixed wire codec, TM/TC integration, key and predefined-SA management,
FSR, and selected monitoring procedures are implemented and covered by module
tests. Their current behavior is documented under
[SDLS design](../design/sdls/index.md) and
[supported features](../reference/supported-features.md).

## Remaining work

- Validate protected TM output and TC input against an independent peer using
  the configured fixed profile and published vectors.
- Add a full-link SDLS case once the inverse ground-side TM/TC harness in the
  [CFDP plan](cfdp-full-link-validation.md) exists.
- Collect on-device ESP32-S3 benchmark values for the supplied benchmark
  sample. The historical build/provider proof found PSA GCM/GMAC using the
  Mbed TLS software path, not the ESP32 AES accelerator.
- Evaluate a PSA-provider integration for accelerated GCM/GMAC only if target
  measurements justify it; do not hide provider selection behind protocol API
  changes.
- Produce a scoped conformance/interoperability record before making any claim
  broader than the supported-feature matrix.

## Acceptance criteria

- Independent peers authenticate/decrypt exact TM and TC vectors for the
  selected profile.
- Tampering, wrong keys, replay, excessive gaps, and unusable SAs fail without
  exposing packet data or mutating receive acceptance state.
- Target measurements identify the resolved PSA provider and distinguish
  software from hardware-assisted operation.
- Test results qualify module, consuming-application, and hardware verification
  separately.

## Out of scope

Dynamic SA creation/deletion, Key Destruction, runtime algorithm negotiation,
AOS/USLP, persistence policy, and mission provisioning remain outside this
plan.
