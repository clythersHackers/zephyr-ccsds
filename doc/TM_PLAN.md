# TM Follow-Up Plan

## Status

The current module implements the TM generation slice:

- per-VC admission of complete encoded Space Packets;
- packet-bearing and idle TM transfer-frame generation;
- internal workqueue-driven cadence;
- route registration and per-VC route masks;
- CLCW insertion through a provider callback;
- optional FECF, randomization, and Reed-Solomon coding;
- focused generator, routing, coding, and failure-path tests.

The original AkiraOS document mixed this completed core with shell commands,
UDP destinations, serial devices, and archive policy. Those consumer-owned
items do not belong in the standalone module plan.

## Remaining Module Work

### Ground-Side Downlink Decode

The inverse TM/CADU path required by full-link CFDP validation is tracked in
[CFDP_PLAN.md](CFDP_PLAN.md). Initially keep profile-specific parsing in the
integration harness. Promote reusable decode primitives only with focused
public-API tests.

### Protocol Follow-Ups

- Add stricter idle Space Packet behavior if a selected interoperable profile
  requires it.
- Clarify configuration terminology for uncoded transfer-frame length versus
  coded output length.
- Evaluate bounded burst generation without replacing the existing internal
  cadence.
- Evaluate per-VC queue sizing or active-VC selection for constrained targets.
- Add conformance vectors for CLCW, FECF, randomization, and coding combinations
  as verified references become available.

## Acceptance Criteria

- Existing generator and routing APIs remain compatible.
- Route callbacks continue to receive already encoded module output.
- New configuration uses only neutral `CONFIG_CCSDS_*` symbols.
- Core TM code remains independent of transports, storage, boards, and
  application policy.
- All frame tests pass on `native_sim`.

## Consumer Responsibilities

Consumers own:

- UDP, UART, RF, CAN, or other concrete route implementations;
- route defaults and shell commands;
- archive format, storage quotas, replay policy, and lifecycle;
- mission VC/APID allocation and product logging.

These features should use `ccsds_tm_frame_register_route()` and
`ccsds_tm_frame_set_vc_route()` rather than adding device policy to the module.
