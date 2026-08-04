# Module configuration reference

Audience: module users selecting compile-time limits and protocol components.
This page is canonical for reusable module defaults. Consuming applications
must document their overrides separately.

| Symbol | Default | Range/dependency | Meaning |
|---|---:|---|---|
| `CONFIG_CCSDS` | `n` | — | Enable the module. |
| `CONFIG_CCSDS_ROUTER_MAX_APIDS` | 8 | 1–64 | APID entries per router. |
| `CONFIG_CCSDS_FRAME_SUPPORT` | `y` | core | Build TM/TC frames and channel coding. |
| `CONFIG_CCSDS_MAX_CLTU_LEN` | 1024 | 64–65535 | Complete CLTU bound. |
| `CONFIG_CCSDS_MAX_FRAME_LEN` | 1115 | 32–65535 | Transfer-frame workspace/length bound. |
| `CONFIG_CCSDS_TC_MAX_SPACE_PACKET_LEN` | 2048 | 7–65535 | TC reassembly capacity. |
| `CONFIG_CCSDS_COP1_WINDOW_SIZE` | 128 | 4–128 | TC sequence acceptance window. |
| `CONFIG_CCSDS_SPACECRAFT_ID` | 123 | 0–1023 | Accepted/emitted spacecraft ID. |
| `CONFIG_CCSDS_TM_MAX_SPACE_PACKET_LEN` | 2048 | 7–65535 | TM packet admission bound. |
| `CONFIG_CCSDS_TM_QUEUE_DEPTH` | max TM packet length | 7–65535 | Bytes stored per TM VC. |
| `CONFIG_CCSDS_RS` | `y` | frame support | Reed-Solomon encoding. |
| `CONFIG_CCSDS_RS_INTERLEAVE_DEPTH` | 5 | 1–8 | Interleaved codewords. |
| `CONFIG_CCSDS_RND` | `n` | frame support | Build randomization primitive. |
| `CONFIG_CCSDS_TM_RND` | `n` | frame support | Randomize TM bytes after ASM. |
| `CONFIG_CCSDS_TC_RND` | `n` | frame support | Derandomize decoded TC bytes. |
| `CONFIG_CCSDS_TM_FECF` | `n` with RS; otherwise `y` | frame support | Append CRC-16 FECF. |
| `CONFIG_CCSDS_UDP` | `y` | hidden | Build bounded-unit UDP adapter. |
| `CONFIG_CCSDS_UDP_MAX_UNIT_LEN` | max CLTU length; otherwise 1024 | 7–65535 | Datagram/workspace bound. |
| `CONFIG_CCSDS_UDP_THREAD_STACK_SIZE` | 2048 | 1024–8192 | Per-instance receive stack. |
| `CONFIG_CCSDS_CFDP` | `n` | core | Build CFDP core and packet adapter. |
| `CONFIG_CCSDS_CFDP_MAX_ENTITY_ID_LEN` | 4 | 1–8 | Entity-ID width bound. |
| `CONFIG_CCSDS_CFDP_MAX_TRANS_SEQ_LEN` | 4 | 1–8 | Transaction sequence width bound. |
| `CONFIG_CCSDS_CFDP_MAX_FILENAME_LEN` | 64 | 0–255 | Filename capacity excluding terminator. |
| `CONFIG_CCSDS_CFDP_MAX_PDU_SIZE` | 512 | 64–65535 | Entity PDU workspace. |
| `CONFIG_CCSDS_CFDP_MAX_SEGMENT_SIZE` | 384 | 1–65535 | File Data segment workspace. |
| `CONFIG_CCSDS_CFDP_MAX_NAK_RANGES` | 4 | 1–64 | Stored/routed missing ranges. |
| `CONFIG_CCSDS_CFDP_MAX_NAK_ROUNDS` | 4 | 1–255 | Recovery retry limit. |
| `CONFIG_CCSDS_SDLS` | `n` | core; PSA AES/GCM | Build fixed SDLS profile. |
| `CONFIG_CCSDS_SDLS_MAX_SA` | 4 | 1–255 | SA slots per context. |
| `CONFIG_CCSDS_SDLS_MAX_KEYS` | 8 | 2–255 | Opaque PSA key slots per context. |
| `CONFIG_CCSDS_SDLS_SESSION_KEY_BASE` | 4 | 1–254 | First session-key ID. |
| `CONFIG_CCSDS_SDLS_ARSN_WINDOW` | 1024 | 1–2147483647 | Maximum receive ARSN forward gap. |
| `CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY` | 8 | 1–255 | Cycling event records per context. |
| `CONFIG_CCSDS_SDLS_IV_SEED_HIGH/LOW` | 0 | 32-bit halves | Deterministic IV seed. |

Dependencies and ranges are enforced by `zephyr/Kconfig`; that file remains
the executable source of truth if this table and a build ever disagree.

