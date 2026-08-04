# SDLS Stage 3 TC/TM integration

This design note records the reusable transfer-frame integration completed in
Stage 3. It uses the fixed Stage 2 wire profile and does not add another
cryptographic, lookup, nonce, replay, authentication-mask, or endian layer.

## TC receive boundary

`ccsds_profile_tc_rx_set_sdls()` configures a caller-owned SDLS context on one
TC receive profile. After CLTU decode, optional derandomization, TC primary
header validation, and accepted-VC selection, the profile distinguishes
Type-D data frames from Type-BC control frames. The mission wire profile keeps
the one-octet TC Segment Header directly after the five-octet TC primary
header. For Type-D frames, the profile passes only the bytes after that clear
segment header to `ccsds_sdls_process_security()` with:

- a TC receive direction;
- the six-octet TC primary-header plus segment-header prefix;
- `ccsds_sdls_tc_default_auth_mask`; and
- the caller-owned bounded workspace embedded in the TC profile.

The segment header, including MAP ID, remains clear but is authenticated as
additional data. The SDLS Security Header therefore begins at byte offset six.
In GCM mode the Space Packet bytes are encrypted and authenticated; in GMAC
mode they remain clear and are authenticated. On success the existing
COP-1/FARM, segment reassembly, and MAP ID/APID routing path receives the
authenticated segment header and clear packet data. On any format, SPI, SA,
key, replay, PSA, or authentication error, the function returns that error
through the existing TC status path before FARM-B, COP-1, reassembly, routing,
or application state changes.

The TC primary and segment headers may be examined before authentication to
establish the transfer-frame boundary, channel, and MAP ID. No packet data and
no state-changing dispatch is exposed before authentication succeeds.

Per CCSDS TC Space Data Link Protocol, Type-BC control frames such as UNLOCK
and SET V(R) do not carry an SDLS Security Header or Security Trailer. They
therefore bypass SDLS and enter the existing control-command path after basic
transfer-frame and configured-channel validation. The reserved service-type
combination with the Control Command Flag set and the Bypass Flag clear is
rejected before FARM or COP-1 state changes.

## TM transmit boundary

`ccsds_tm_frame_set_sdls()` configures a caller-owned SDLS context and the SPI
of its operational TM transmit SA. Every subsequent packet-bearing or idle TM
frame reserves the fixed 30-octet protected overhead:

```text
6-octet TM primary header
14-octet SDLS Security Header
encrypted Frame Data
16-octet authentication tag
4-octet OCF
optional 2-octet FECF
```

The formatter fills the reduced Frame Data capacity, constructs the primary
header, and calls `ccsds_sdls_apply_security()` in GCM mode with
`ccsds_sdls_tm_default_auth_mask`. It then inserts the OCF, computes the FECF
over the complete secured transfer frame, and performs Reed-Solomon coding and
randomization as configured. The First Header Pointer remains relative to the
start of Frame Data. The pre-existing coded-frame buffer is reused as the
temporary SDLS workspace and is overwritten by channel coding afterward; no
additional global work buffer or heap storage is introduced.

The fixed-size compile assertions require enough transfer-frame and existing
coded-buffer capacity for the primary header, security overhead, OCF, FECF,
and SDLS workspace.

## Compatibility and scope

When `CONFIG_CCSDS_SDLS` is disabled, the SDLS context fields and configuration
APIs are absent and the original TC and TM paths compile unchanged. When it is
enabled, a profile remains clear until its SDLS setter is called.

This stage does not provision keys or SAs. The application initializes the
caller-owned context with the Stage 2 APIs and opaque PSA key identifiers.
OTAR, Extended Procedures, FSR generation, SA management, persistence,
runtime SA creation/deletion, and Akira application provisioning remain
outside Stage 3.
