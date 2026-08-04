# Public API reference

Audience: module users checking ownership and integration contracts. Public
declarations in `include/ccsds/` remain the source of truth for signatures.

| Component | Primary API | Contract summary |
|---|---|---|
| Space Packet | `ccsds_space_packet_encode/decode()`, `ccsds_space_packet_encoded_len()` | Complete packet buffers; decoded payload is a view into input. |
| APID router | `ccsds_router_init()`, `ccsds_router_register_apid()`, dispatch functions | Caller-owned fixed table; handler return propagates. |
| TC frame/segment | `ccsds_tc_frame_*`, `ccsds_tc_segment_*` | Decode and views over caller buffers. |
| CLTU/BCH | `ccsds_cltu_decode_message()`, `ccsds_bch_decode_block()` | Complete bounded CLTU/block; streaming push is unsupported. |
| TM | `ccsds_tm_frame_init()`, route registration/masks, packet admission, start/stop | One module-global generator; callbacks receive encoded output on system work queue. |
| Profiles | `ccsds_profile_*` | Caller-owned TC composition or bounded packet-only input. |
| UDP | `ccsds_udp_init/start/stop/send()`, `ccsds_udp_dispatch_datagram()` | Caller-owned instance; config strings/context outlive use; callback buffer is call-scoped. |
| CFDP entity | `ccsds_cfdp_entity_*` | Caller-owned synchronous entity; serialize access and poll monotonically. |
| CFDP packet adapter/service | `ccsds_cfdp_space_packet_adapter_*`, `ccsds_cfdp_service_*` | Owns packet buffer/sequence and composes entity; router, filestore, and callbacks remain caller-owned. |
| SDLS | `ccsds_sdls_init()`, `ccsds_sdls_apply_security()`, `ccsds_sdls_process_security()` | Caller-owned fixed context/workspace; key bytes remain in PSA; malformed wire input returns stable errors. |
| SDLS EP/FSR | `ccsds_sdls_ep_*`, FSR and Self Test registration APIs | Fixed PDU/workspace bounds; recipient output is transactional; application owns authorization and diagnostics. |

`ccsds_udp_init()` copies its configuration but not strings or callback
context. `ccsds_udp_start()` creates one receive thread; `stop()` must complete
before destroying referenced objects. A datagram above the instance limit is
rejected as a whole. Without networking, availability is false and socket
start/send return `-ENOTSUP`, while direct dispatch remains usable by another
bounded-unit adapter.

Programmer contract violations such as null required storage, undersized
caller workspaces, duplicate static descriptors, or impossible configuration
assert. Expected wire, runtime, transport, capacity, and PSA failures use the
documented return values.

