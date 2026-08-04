# TC streaming and follow-up plan

## Status

The module already implements the current bounded telecommand receive slice:

- complete-message CLTU validation and BCH decode;
- TC transfer-frame decode and spacecraft-ID validation;
- supported COP-1/FARM acceptance and CLCW generation;
- TC segment parsing and bounded Space Packet reassembly;
- APID routing through the neutral input profile;
- focused tests for malformed input, control commands, sequencing,
  segmentation, reassembly, and CLCW behavior.

The original AkiraOS plan described this work before extraction. Its paths,
Kconfig names, and most of its checklist are obsolete. Application commands,
shell presentation, UDP endpoint policy, and harmless platform test APIDs
remain consumer responsibilities.

## Remaining Module Work

### Streaming CLTU Acquisition

`ccsds_cltu_rx_push()` currently returns `-ENOTSUP`. Implement it only when a
byte-stream transport needs incremental acquisition rather than complete
bounded CLTUs.

Requirements:

- accept arbitrarily split start, BCH block, and tail sequences;
- bound storage with `CONFIG_CCSDS_MAX_CLTU_LEN`;
- recover after malformed or oversized input;
- invoke the registered callback once per complete decoded TC frame;
- preserve `ccsds_cltu_decode_message()` as the complete-message primitive;
- add split-boundary, noise, overflow, resynchronization, and back-to-back CLTU
  tests.

### Conformance And Diagnostics

- Add vectors for any supported CLTU fill forms not already covered.
- Expand COP-1/FARM edge-case tests only from verified references.
- Keep reject causes distinguishable without dumping command contents.
- Add neutral counter APIs only when more than one consumer requires them.

### Ground-Side Uplink Support

The TC/CLTU encoding needed for the full-link CFDP test is tracked in the
[CFDP full-link plan](cfdp-full-link-validation.md). Keep test-only
construction helpers out of the public API unless they become independently
reusable.

## Acceptance Criteria

- Existing bounded complete-CLTU behavior and public APIs remain compatible.
- New work uses only neutral `CONFIG_CCSDS_*` symbols.
- Core TC code remains transport-independent.
- All frame tests pass on `native_sim`.

## Out Of Scope

- AkiraOS shell commands, ports, endpoint selection, or product logging.
- Platform command handlers and command side effects.
- Board, DTS, radio, UART, or filesystem policy.
- Unverified expansion of COP-1 behavior.
