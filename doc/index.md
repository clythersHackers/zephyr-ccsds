# CCSDS module user guide

## Scope

The CCSDS Zephyr module implements selected parts of these CCSDS protocol
families:

- Space Packet Protocol: version 0 primary-header encoding and decoding,
  packet length handling, TC/TM type, secondary-header flag, APID, sequence
  flags, and 14-bit sequence count.
- Telecommand (TC) Space Data Link Protocol: version 0 transfer-frame decoding,
  10-bit spacecraft ID validation, 64 virtual-channel IDs, bypass/control
  flags, frame sequence number, segment-header decoding, and packet-fragment
  walking.
- Telemetry (TM) Space Data Link Protocol: fixed-length version 0 transfer
  frames for virtual channels 0 through 7, Space Packet queuing and
  continuation, idle data, master and virtual-channel counters, OCF/CLCW
  insertion, optional FECF, and callback-based output routing.
- TC Synchronization and Channel Coding: complete-CLTU decoding with the
  standard start and tail sequences and BCH(63,56) correction/detection.
- TM Synchronization and Channel Coding: attached synchronization marker,
  optional interleaved Reed-Solomon (255,223) parity, and optional
  randomization.
- CCSDS File Delivery Protocol (CFDP), version 1: small-file Metadata, File
  Data, EOF, Finished, ACK, and NAK PDUs; acknowledged and unacknowledged file
  transfer; closure; missing-range recovery; and modular, CRC-32C,
  IEEE 802.3 FCS, and null file checksums.
- Space Data Link Security (SDLS): fixed-capacity caller-owned Security
  Association/key state, strict fixed-profile header/trailer codecs,
  deterministic IV allocation, bounded receive replay protection, and
  transport-independent AES-256-GCM/GMAC processing through PSA.

This guide describes the implemented subset, not the complete CCSDS standards.
The standards themselves are not distributed with this module.

## Add the module to an application

Make this repository a Zephyr module by adding it as a west manifest project
or by passing its absolute path in `ZEPHYR_EXTRA_MODULES`. Zephyr discovers
`zephyr/module.yml`, which loads the module Kconfig and CMake files. Application
code includes public headers with paths such as:

```c
#include <ccsds/ccsds_space_packet.h>
```

Enable the core in `prj.conf`:

```ini
CONFIG_CCSDS=y
```

Frame support is enabled by default. CFDP and randomization are opt-in. The UDP
bounded-unit adapter is compiled with the core; socket operation additionally
requires Zephyr networking (`CONFIG_NETWORKING=y`).

## Configuration

All module Kconfig symbols use the `CONFIG_CCSDS_*` namespace.

| Symbol | Default | Range/dependency | Meaning |
|---|---:|---|---|
| `CONFIG_CCSDS` | `n` | — | Enable the module. |
| `CONFIG_CCSDS_ROUTER_MAX_APIDS` | 8 | 1–64; `CCSDS` | APID router entries per caller-owned router. |
| `CONFIG_CCSDS_FRAME_SUPPORT` | `y` | `CCSDS` | Build TC/TM frame, segmentation, BCH, and CLTU support. |
| `CONFIG_CCSDS_MAX_CLTU_LEN` | 1024 | 64–65535; frame support | Maximum complete CLTU and streaming receiver buffer. |
| `CONFIG_CCSDS_MAX_FRAME_LEN` | 1115 | 32–65535; frame support | TC workspace and non-RS TM frame length ceiling. |
| `CONFIG_CCSDS_TC_MAX_SPACE_PACKET_LEN` | 2048 | 7–65535; frame support | TC profile reassembly capacity. |
| `CONFIG_CCSDS_COP1_WINDOW_SIZE` | 128 | 4–128; frame support | TC sequence acceptance window. |
| `CONFIG_CCSDS_SPACECRAFT_ID` | 123 | 0–1023; frame support | TC accepted and TM emitted spacecraft ID. |
| `CONFIG_CCSDS_TM_MAX_SPACE_PACKET_LEN` | 2048 | 7–65535; frame support | Largest packet admitted to TM. |
| `CONFIG_CCSDS_TM_QUEUE_DEPTH` | `CCSDS_TM_MAX_SPACE_PACKET_LEN` | 7–65535; frame support | Bytes stored per TM virtual channel; must hold one maximum packet. |
| `CONFIG_CCSDS_RS` | `y` | frame support | Build and apply Reed-Solomon encoding to TM output. |
| `CONFIG_CCSDS_RS_INTERLEAVE_DEPTH` | 5 | 1–8; `CCSDS_RS` | Number of interleaved RS codewords. |
| `CONFIG_CCSDS_RND` | `n` | frame support | Build the randomization primitive. |
| `CONFIG_CCSDS_TM_RND` | `n` | frame support; selects `CCSDS_RND` | Randomize TM bytes after the ASM. |
| `CONFIG_CCSDS_TC_RND` | `n` | frame support; selects `CCSDS_RND` | Derandomize decoded TC frame bytes. |
| `CONFIG_CCSDS_TM_FECF` | `n` with RS, otherwise `y` | frame support | Append a CRC-16 FECF to TM frames. |
| `CONFIG_CCSDS_UDP` | `y` | hidden; `CCSDS` | Build the bounded-unit UDP adapter. |
| `CONFIG_CCSDS_UDP_MAX_UNIT_LEN` | max CLTU length, or 1024 without frames | 7–65535; UDP | Receive workspace and maximum configured datagram. |
| `CONFIG_CCSDS_UDP_THREAD_STACK_SIZE` | 2048 | 1024–8192; UDP | Stack bytes embedded in each UDP instance. |
| `CONFIG_CCSDS_CFDP` | `n` | `CCSDS`; selects `CRC` | Build CFDP core and Space Packet composition. |
| `CONFIG_CCSDS_CFDP_MAX_ENTITY_ID_LEN` | 4 | 1–8; CFDP | Maximum encoded entity ID length. |
| `CONFIG_CCSDS_CFDP_MAX_TRANS_SEQ_LEN` | 4 | 1–8; CFDP | Maximum transaction sequence number length. |
| `CONFIG_CCSDS_CFDP_MAX_FILENAME_LEN` | 64 | 0–255; CFDP | Filename array capacity excluding the terminator. |
| `CONFIG_CCSDS_CFDP_MAX_PDU_SIZE` | 512 | 64–65535; CFDP | Entity PDU workspace and Space Packet payload ceiling. |
| `CONFIG_CCSDS_CFDP_MAX_SEGMENT_SIZE` | 384 | 1–65535; CFDP | File Data segment workspace. |
| `CONFIG_CCSDS_CFDP_MAX_NAK_RANGES` | 4 | 1–64; CFDP | Stored missing ranges and ranges per NAK. |
| `CONFIG_CCSDS_CFDP_MAX_NAK_ROUNDS` | 4 | 1–255; CFDP | Recovery retry limit. |
| `CONFIG_CCSDS_SDLS` | `n` | `CCSDS`; selects PSA AES/GCM support | Build fixed-profile SDLS state and wire processing. |
| `CONFIG_CCSDS_SDLS_MAX_SA` | 4 | 1–255; SDLS | SA state slots embedded in each SDLS context. |
| `CONFIG_CCSDS_SDLS_MAX_KEYS` | 8 | 2–255; SDLS | Opaque PSA key-reference slots embedded in each SDLS context. |
| `CONFIG_CCSDS_SDLS_SESSION_KEY_BASE` | 4 | 1–254; SDLS | First Key ID assigned to a session-key slot; lower IDs are master-key slots. |
| `CONFIG_CCSDS_SDLS_ARSN_WINDOW` | 1024 | 1–2147483647; SDLS | Maximum accepted forward gap from the last authenticated receive ARSN. |
| `CONFIG_CCSDS_SDLS_IV_SEED_HIGH/LOW` | 0 | 32-bit hex halves; SDLS | Fixed high and low halves of the deterministic IV seed. |

With RS enabled, the TM transfer-frame body is
`223 * CONFIG_CCSDS_RS_INTERLEAVE_DEPTH` bytes and must fit
`CONFIG_CCSDS_MAX_FRAME_LEN`. Without RS, the configured maximum frame length
is the emitted TM frame length.

## Memory and ownership

The module does not allocate protocol state from the heap. Routers, TC profiles,
UDP adapters, CFDP entities, adapters, services, and their configuration/user
objects are caller-owned and must remain valid while in use.

Important static or embedded costs include:

- each router: `CONFIG_CCSDS_ROUTER_MAX_APIDS` entries;
- each TC receive profile: one maximum TC packet reassembly buffer and one
  maximum frame buffer;
- TM: module-global queues of `CONFIG_CCSDS_TM_QUEUE_DEPTH` bytes for each of
  eight virtual channels, plus global frame/coded-frame workspaces;
- each UDP instance: a receive buffer of
  `CONFIG_CCSDS_UDP_MAX_UNIT_LEN + 1`, a configured thread stack, sockets,
  counters, and synchronization objects;
- each CFDP entity: one PDU buffer, one file-segment buffer, one sender slot,
  one receiver slot, filename arrays, checksum state, and missing ranges;
- each CFDP Space Packet adapter: a primary-header-plus-maximum-PDU packet
  buffer.
- each default SDLS context: 144 bytes for four SA/receive-counter states,
  eight opaque PSA key/transmit-counter records, and compact profile arrays.
  Operational key bytes and caller-owned crypto workspaces are not stored in
  the context.

Decoded Space Packet, TC frame, TC segment, and CFDP PDU payload pointers are
views into caller-provided encoded buffers. Keep those buffers alive until the
view is no longer used. Transport receive buffers are only valid for the
duration of the receive callback unless the application copies them.

## Packet, frame, coding, and profile APIs

`ccsds_space_packet_encode()` and `ccsds_space_packet_decode()` operate on
complete Space Packets. `ccsds_space_packet_encoded_len()` reports the required
primary-header-plus-payload size.

`struct ccsds_router` is an instance-based, fixed-capacity APID dispatch table.
Initialize it, register or replace handlers with
`ccsds_router_register_apid()`, and dispatch either a decoded packet or encoded
packet bytes. Handler return values propagate to the caller.

Frame-support builds provide:

- `ccsds_tc_frame_decode()` and `ccsds_tc_frame_extract_packet()` for bounded
  TC frames;
- TC segment decode and packet/fragment walking through
  `ccsds_tc_segment_*`;
- `ccsds_cltu_decode_message()` for a complete bounded CLTU and
  `ccsds_bch_decode_block()` for a single BCH block;
- `ccsds_rnd_apply()`, which is self-inverse, and
  `ccsds_rs_encode()` for interleaved parity generation;
- `ccsds_tm_frame_*` for global TM initialization, route callback
  registration, per-VC route masks, optional CLCW provisioning, packet
  admission, and a delayable-work generator; and
- `ccsds_profile_*` composition helpers for complete-CLTU TC reception,
  one accepted TC virtual channel, segment reassembly, a limited COP-1
  acceptance/CLCW state, and packet-only bounded input when frame support is
  disabled.

TM route names are identifiers for callback bits; the application supplies the
actual log, archive, UART, UDP, CAN, or rate-class implementation. Start the TM
generator only after initialization, route registration, and route-mask
selection. It selects the lowest numbered VC with pending data and emits idle
frames on VC 7 when no data is queued. Route callbacks run from the system work
queue and their return values are not retried by the TM generator.

## Transport boundary and UDP adapter

Protocol engines exchange bounded units through callbacks:

- the APID router invokes packet handlers;
- TM invokes registered output-route callbacks;
- CFDP Unitdata Transfer invokes `send_pdu` and `now_ms`;
- the CFDP Space Packet adapter invokes an encoded-packet send callback; and
- the UDP adapter invokes one receive callback per accepted datagram and
  exposes `ccsds_udp_send()` as a compatible bounded-unit sender.

These boundaries do not prescribe UDP, UART, radio, or another device type.

## SDLS wire processing

With `CONFIG_CCSDS_SDLS=y`, include `<ccsds/ccsds_sdls.h>` and allocate one
`struct ccsds_sdls_ctx` in caller-owned storage. `ccsds_sdls_init()` places
static SA roles, modes, mutable initial state, and key metadata into inline
arrays. It never creates or deletes an SA and never retains operational key
bytes.

The configured SPI range is dense and one-based: wire SPI `1..MAX_SA` maps
directly to SA slot `spi - 1`; reserved SPI zero is never used. Key IDs
`0..MAX_KEYS-1` map directly to key slots. IDs below
`CONFIG_CCSDS_SDLS_SESSION_KEY_BASE` are master keys and IDs at or above it
are session keys. Neither identifier nor key role is stored redundantly, and
lookup performs no search. Unconfigured slots remain distinguishable from
configured entries. Duplicate identifiers, unknown referenced keys, malformed
metadata, and capacity overflow are static configuration errors and assert.

`ccsds_sdls_apply_security()` accepts a compact, optionally bit-masked
transfer-frame header plus one clear data span. Only the mask prefix through
the final zero byte is stored; later bytes are implicitly all ones. TM and TC
default mask arrays are provided from the standard profile. The call
writes Security Header, protected data, and Security Trailer to caller
storage.
`ccsds_sdls_process_security()` selects a receive SA solely by the decoded SPI
and exposes clear data only after tag and replay checks succeed. Both calls
require a caller-owned workspace; null or undersized caller buffers assert,
while malformed received wire data returns a stable error.
The fixed wire profile uses a big-endian SPI, complete 96-bit IV, and 128-bit
tag. Receive state is a strictly increasing ARSN with a configurable maximum
forward gap, not a replay bitmap. Transmit state is one volatile counter per
key; following reset, a fresh session key must be installed by OTAR before
protected transmission resumes. See
[the Stage 2 profile](SDLS_STAGE2_WIRE.md) for exact masking, anti-replay,
reset policy, and footprint rules.

For UDP, allocate one `struct ccsds_udp` per endpoint and provide local/peer
IPv4 addresses, ports, maximum unit length, receive callback, thread priority,
and optional thread name. `ccsds_udp_init()` copies the configuration but not
the strings or callback context. `ccsds_udp_start()` binds a socket and starts
one receive thread per instance. The receive callback runs synchronously in
that thread and must not retain the receive buffer. A datagram larger than the
instance limit is rejected as a whole. `ccsds_udp_send()` lazily creates a send
socket and preserves datagram boundaries.

`ccsds_udp_available()` reports whether networking was compiled in. Without
networking, start/send return `-ENOTSUP`; direct
`ccsds_udp_dispatch_datagram()` remains useful for adapting another
bounded-unit source. Call `ccsds_udp_stop()` before destroying or reusing the
instance or any strings/user context referenced by its copied configuration.
Statistics are mutex-protected snapshots. Calls for a single instance may be
made by multiple threads, but initialization and lifetime transitions must be
coordinated by the application.

## CFDP integration

Enable `CONFIG_CCSDS_CFDP` and supply two application boundaries:

1. `struct ccsds_cfdp_filestore_ops` opens source files, creates temporary
   destination files, performs offset reads/writes, closes handles, and either
   commits or discards the temporary destination. Paths are opaque to the
   protocol engine. Handles and all backing storage belong to the application.
2. `struct ccsds_cfdp_ut_ops` sends one PDU to a destination entity and
   optionally supplies monotonic milliseconds. The transport must deliver
   received PDU bytes to `ccsds_cfdp_entity_receive_pdu()`.

The entity supports one active sender and one active receiver. Sending reads
the file through the filestore, emits Metadata/File Data/EOF, and reports
events. Receiving uses random-access writes, verifies size/checksum, then
commits or discards the temporary file. CRC checksums received out of order
require the filestore to support rereading the completed temporary file.

`struct ccsds_cfdp_space_packet_adapter` maps CFDP PDUs to complete Space
Packets. It owns packet sequence state and a packet buffer, returns Unitdata
Transfer operations for an entity, and registers its local APID with a
caller-owned router for reception.

`struct ccsds_cfdp_service` composes one entity and one Space Packet adapter.
Initialize it with entity IDs, APIDs, packet type, send/time callbacks,
receive filestore, and optional event callback; register it with a router; use
`ccsds_cfdp_service_send_file()` for transmission; and poll it. Multiple
service instances keep independent entity and packet-sequence state, but their
routers, filestores, callbacks, and callback contexts remain caller-owned.

The entity is synchronous and does not create a thread. Serialize calls that
touch one entity/service, or call them from one owner thread. Poll with
monotonically increasing milliseconds often enough to service recovery
deadlines. The current retry interval is 1000 ms; acknowledged-mode EOF,
Finished, and NAK recovery is retried until the configured maximum NAK rounds
is reached. A transport callback failure is returned to the initiating call;
the application retains responsibility for transport availability.

## Stable subset limitations

- Space Packet secondary-header contents are opaque payload bytes.
- TC encoding is not provided. TC decode accepts version 0 and the configured
  spacecraft ID. The complete-CLTU decoder is supported, while streaming
  `ccsds_cltu_rx_push()` returns `-ENOTSUP`.
- The TC profile models one accepted virtual channel and a limited receiving
  COP-1/FARM/CLCW path, including Set V(R), sequence acceptance, retransmit,
  and lockout behavior. It is not a general COP-1 implementation.
- TM state and buffers are module-global, so there is one TM generator per
  image. It supports eight VCs and fixed-length frames. Reed-Solomon encoding
  is provided; Reed-Solomon decoding is not.
- CFDP supports small files with 32-bit sizes/offsets, one configured remote
  entity per entity instance, one simultaneous sender and receiver, and the
  listed PDU directives/checksums. Large-file mode, segment metadata, Metadata
  options/TLV procedures, and empty filenames are rejected.
- A CFDP PDU CRC-present flag can be encoded/decoded, but PDU CRC validation
  and generation are not performed by this subset.
- The module provides callback contracts, not a filesystem implementation,
  endpoint policy, device discovery, or automatic service startup.

## Build, run, and test

Build and run the deterministic Space Packet sample from a Zephyr workspace:

```sh
west build -b native_sim samples/space_packet \
  -d build/ccsds-space-packet
./build/ccsds-space-packet/zephyr/zephyr.exe
```

Expected line:

```text
CCSDS Space Packet round trip OK: APID=1 sequence=42 payload=deadbeef
```

Stop the native simulator with Ctrl+C after the result is printed.

Run module tests and sample verification:

```sh
west twister -T tests -p native_sim --inline-logs
west twister -T samples -p native_sim --inline-logs
```

The module tests cover primitives, frames/profiles, CFDP, and module discovery.
The sample metadata separately verifies the developer-facing example.
