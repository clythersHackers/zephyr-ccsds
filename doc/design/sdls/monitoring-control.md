# SDLS monitoring and control

## Scope

This profile implements the selected CCSDS 355.1-B-1 Security Monitoring and
Control procedures on the existing authenticated Extended Procedures packet
route:

- Ping (PID 1);
- Log Status (PID 2);
- Dump Log (PID 3);
- Erase Log (PID 4);
- Self Test (PID 5); and
- Alarm Flag Reset (PID 7).

Key Destruction, Create SA, Delete SA, persistent logging,
user-defined procedures, and application/board diagnostics are not included.

## Wire profile

The Extended Procedures service group is binary `11`. The common three-octet
header is the one-octet tag followed by a big-endian 16-bit data-field length
in bits. Every declared length must be octet aligned and describe all remaining
PDU octets exactly.

| Procedure | Command | Reply |
|---|---|---|
| Ping | `31 0000` | `b1 0000` |
| Log Status | `32 0000` | `b2 0020 <retained:u16> <remaining:u16>` |
| Dump Log | `33 0000` | `b3 <N*80 bits> <N event TLVs>` |
| Erase Log | `34 0000` | `b4 0020 <retained:u16> <remaining:u16>` |
| Self Test | `35 0000` | `b5 0008 <result:u8>` |
| Alarm Flag Reset | `37 0000` | no reply PDU |

The table shows hexadecimal octets. The default successful Erase Log reply is
`b4 0020 0000 0008`. Self Test result `00` is OK and `80` is not OK; this
profile fixes all standard implementation-defined low result bits to zero.

Each Dump Log event is a managed nested TLV:

```text
Event Message Tag       1 octet
Event Message Length    2 octets, big endian, value 7 (octets)
Event Message Value     7 octets:
  event code            1 octet
  SPI                   2 octets, big endian
  ARSN                  4 octets, big endian
```

The outer Dump Log PDU length remains measured in bits. The nested Event
Message Length is measured in octets, matching the selected managed reference
form. Empty dumps contain only `b3 0000`.

## Compact event log

Every caller-owned SDLS context embeds
`CONFIG_CCSDS_SDLS_EVENT_LOG_CAPACITY` ordinary host records. Its default is
eight. Each record is exactly eight octets:

```c
uint8_t  pdu_or_event_tag;
uint8_t  event_code;
uint16_t spi;
uint32_t arsn;
```

This is not a wire structure. Dump Log encodes every multioctet field
explicitly. Build assertions cover the host record size, ring indices, maximum
Dump Log PDU size, and 16-bit length representability.

The ring continuously retains the newest events. At capacity, insertion
replaces only the oldest record, advances the oldest index, and leaves the
retained count at capacity. Dumps are stable oldest-to-newest snapshots and do
not mutate the ring. A saturating one-octet overwrite counter is available in
the context for local diagnostics but is never transmitted.

Log Status and Erase Log use big-endian 16-bit counts. A full ring reports
`capacity, 0`; overwrite does not change that result.

## Stable event codes and tags

| Value | Meaning |
|---:|---|
| 1 | malformed or inconsistent input |
| 2 | authentication/MAC failure |
| 3 | stale or duplicate ARSN |
| 4 | excessive forward ARSN gap |
| 5 | unknown SPI/SA |
| 6 | unusable SA state, role, or direction |
| 7 | invalid or unavailable key identifier |
| 8 | invalid or incompatible key state |
| 9 | failed key transition |
| 10 | failed SA transition |
| 11 | OTAR master-key authentication failure |
| 12 | Self Test failure |
| 13 | PSA operation failure |
| 14 | unsupported procedure or operation |
| 15 | bounded-capacity failure |

The mapping is explicit; negative module errors are never narrowed or cast to
an event octet. Context-specific recipient failures refine the generic mapping
to key transition, SA transition, OTAR authentication, or Self Test codes.

For a routed EP failure, Event Message Tag is the received EP PDU tag and the
SPI/ARSN come from its authenticated carrying frame. These values are
monitoring provenance only. They do not authorize a procedure, replace a
target SPI/ARSN in an EP PDU, or alter procedure semantics.

Tag `ff` denotes a transfer-frame security failure. Its SPI/ARSN, when a
Security Header was decoded, are explicitly unauthenticated observations. Tag
`fe` denotes a local recipient call without authenticated carrier provenance;
its SPI and ARSN are zero.

ProcessSecurity marks provenance valid only after authentication and replay
acceptance. The TC profile keeps it valid while synchronously walking packets
from that frame, then clears the validity flag and zeroes both fields on every
dispatch exit. Direct recipient transactions similarly invalidate provenance
when they finish.

Successful frame processing, replay acceptance, COP-1/FARM handling, packet
delivery, Ping, EP commands, key/SA operations, replies, and normal FSR updates
do not create records.

## Erase and alarm reset

Erase Log validates the complete empty command and reply capacity before
mutation. It wipes all record storage and resets retained count, indices, and
overwrite count. It preserves FSR flags and last values, replay state, SA/key
state, PSA keys, transmit allocation, OCF phase, and COP-1 state.

Alarm Flag Reset remains separate. It clears the selected FSR alarm and error
condition bits while preserving FSR last SPI/ARSN indication, the event ring,
security state, replay state, transmit allocation, and OCF phase.

## Self Test callback

`ccsds_sdls_set_self_test()` registers a caller callback and opaque user
pointer. The callback receives a result output and must return zero with either
`CCSDS_SDLS_SELF_TEST_OK` or `CCSDS_SDLS_SELF_TEST_NOT_OK`.

- OK produces result `00` and no event.
- A reported not-OK result produces `80` and a Self Test event.
- A missing callback or a callback error/unsupported operation produces `80`
  and a Self Test event; it can never produce a passing result.
- A callback that returns zero with any other result is rejected as malformed;
  the recipient reply output and length remain unchanged.

The reusable module supplies no board-specific diagnostic. Application
integration may register one separately.

## Data exclusion and bounds

Event records and monitoring replies contain only the documented tag, stable
code, SPI, ARSN, counts, and Self Test result. They never contain key material,
opaque-key internals, OTAR plaintext, authentication tags, challenges,
ciphertext, IVs, decrypted packets, or complete packets/frames.

All state and reply bounds are compile-time fixed. No heap, packed wire
structure, C wire bitfield, dynamic table, persistent storage, or module-global
monitoring workspace is used.
