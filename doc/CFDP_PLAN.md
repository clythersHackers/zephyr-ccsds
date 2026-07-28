# CFDP Full-Link Validation Plan

## Status

The reusable CFDP codec, transaction engine, Space Packet adapter, bounded UDP
adapter, and packet-level two-peer integration test are implemented. The
remaining protocol-module milestone is validation over an asymmetric CCSDS
link:

```text
ground -> TC frame/segment -> CLTU -> spacecraft
spacecraft -> TM transfer frame/CADU -> ground
```

This document replaces the pre-extraction CFDP stages 1 through 30. Stages 1
through 29 are historical implementation work and are preserved in Git
history. Artifact installation remains consumer policy and is not part of this
module.

## Goal

Prove that the existing CFDP service can transfer a file without changes while
its Space Packets travel through realistic TC uplink and TM downlink paths.
Keep the ground-side tooling deterministic and suitable for automated
`native_sim` testing.

## Current Building Blocks

- CFDP PDU codecs, checksums, range tracking, Class 1 closure, and bounded
  missing-range recovery.
- One-CFDP-PDU-per-Space-Packet adaptation.
- TC CLTU decode, TC transfer-frame decode, COP-1/FARM state, TC segmentation,
  and APID dispatch.
- TM transfer-frame generation, CLCW insertion, optional FECF, randomization,
  Reed-Solomon coding, and route callbacks.
- A packet-level UDP integration harness covering intact transfer, dropped
  data recovery, and checksum failure.

The module does not yet provide the complete ground-side inverse path needed
by this test. In particular, the harness needs a bounded way to construct the
selected TC/CLTU profile and to decode the selected TM/CADU profile.

## Scope

### 1. Define One Test Link Profile

Record the exact TC frame, segment, CLTU, TM frame, coding, APID, spacecraft
ID, VCID, and maximum-length choices used by the test. Use existing neutral
`CONFIG_CCSDS_*` symbols. Do not encode AkiraOS board or application policy in
the profile.

### 2. Add Ground-Side Test Helpers

Add only the inverse operations required by the selected profile:

- encode a CFDP Space Packet into a TC segment and transfer frame;
- encode the TC frame into a complete CLTU;
- accept routed TM output and undo the configured channel coding;
- decode the TM transfer frame and extract complete Space Packets.

Keep helpers test-owned unless a primitive is independently useful to normal
module consumers. Promoting a helper to the public API requires focused unit
tests and must not redesign existing APIs.

### 3. Exercise Both Directions

Use two CFDP service instances or a ground test entity and a spacecraft test
entity. The same reusable CFDP service must run unchanged above the packet
boundary.

- Uplink: CFDP PDU -> Space Packet -> TC frame/segment -> CLTU -> APID router.
- Downlink: CFDP PDU -> Space Packet -> TM frame/CADU -> ground parser -> CFDP.
- Inject at least one dropped data unit and demonstrate bounded NAK recovery.
- Inject corruption and demonstrate failure rather than a committed file.

### 4. Automate The Test

Provide a repeatable native integration command under `tests/`. Temporary
files and generated frames belong in the test output directory and must remain
untracked.

## Acceptance Criteria

- A small arbitrary binary file crosses the complete asymmetric link path and
  matches byte-for-byte.
- The receiving CFDP entity reports the expected file size and checksum.
- A dropped data unit is recovered within configured retry limits.
- Corrupted data is rejected and is not committed.
- TC acceptance updates the CLCW carried by subsequent TM output.
- The existing packet-level CFDP integration test and all module tests remain
  green.
- No AkiraOS source, filesystem layout, shell policy, board configuration, or
  application lifecycle logic enters this repository.

## Verification

```sh
west twister -T tests -p native_sim --inline-logs
west twister -T samples -p native_sim --inline-logs
tests/cfdp_udp/run_cfdp_udp_integration.sh
```

Add the full-link integration command to this list when the harness lands.

## Non-Goals

- Artifact manifests, signature policy, activation, or rollback.
- Mission-specific radio, UART, filesystem, or board integration.
- Full CFDP feature coverage beyond the currently supported subset.
- COP-1 expansion unrelated to the selected validation path.
- Committing CCSDS standards, copied standard text, or redistribution-unclear
  reference artifacts.
