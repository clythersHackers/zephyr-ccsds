# Supported features

Audience: module users and developers checking the exact implemented subset.
“Verified” below means covered by repository tests; it does not imply
independent interoperability or hardware-link verification.

## Protocol matrix

| Area | Implemented module path | Current restriction |
|---|---|---|
| Space Packet | Version-0 encode/decode, length fields, APID and sequence fields, APID routing | Secondary-header contents are opaque. |
| TC | Version-0 decode, complete CLTU/BCH, segmentation/reassembly, one-VC COP-1/FARM subset, UNLOCK and SET V(R) | No TC encoder; streaming CLTU push unsupported. |
| TM | Eight VCs, fixed frames, queues, idle, counters, OCF/CLCW, FECF, randomization, RS encode, routes | One module-global generator; no RS decoder. |
| UDP | Caller-owned bounded-datagram adapter | IPv4 socket operation requires Zephyr networking. |
| CFDP v1 | Small-file Metadata, File Data, EOF, Finished, ACK, NAK; acknowledged and unacknowledged flows; closure and bounded recovery | 32-bit size/offset; one remote entity, sender, and receiver per entity; no large-file mode, segment metadata, options/TLV procedures, or empty names. |
| CFDP checksums | Modular, CRC-32C, IEEE 802.3 FCS, null | PDU CRC flag is encoded/decoded but PDU CRC generation/validation is not implemented. |
| SDLS | Fixed-capacity AES-256-GCM/GMAC profile, predefined SAs, replay gap, EP subset, FSR and event log | No runtime algorithms, dynamic SA allocation, or general CCSDS 355.1 conformance claim. |

## SDLS Extended Procedures

The supported service groups are Key Management (`00`), SA Management (`01`),
and Security Monitoring and Control (`11`). User-defined tags (bit 6), the
reserved service group, unknown procedures, non-octet lengths, truncation,
trailing bytes, and arbitrary nested TLVs are rejected. The only nested TLV is
the fixed managed Event Message form in Dump Log.

| Service group | Procedure | Command | Reply | Restriction |
|---|---|:---:|:---:|---|
| Key | OTAR | yes | no | Session destinations only; bounded atomic multi-key transaction. |
| Key | Activation | yes | no | Pre-Active session keys only. |
| Key | Deactivation | yes | no | Active or Pre-Active session keys. |
| Key | Verification | yes | yes | Pre-Active or Active session keys. |
| Key | Key Inventory | yes | yes | Authenticated protected receive carrier required; returns present slots only. |
| Key | Key Destruction | no | no | Unsupported. |
| SA | Read ARSN | yes | yes | Receive SAs only. |
| SA | Set ARSN Window | yes | no | Receive SAs; cannot exceed compiled maximum. |
| SA | Rekey SA | yes | no | Predefined Expired SA and Active session key; RX/TX wire forms differ. |
| SA | Expire SA | yes | no | Predefined SA only. |
| SA | Set ARSN | yes | no | Receive SAs; cannot move initialized state backward. |
| SA | Start SA | yes | no | Predefined SA; authenticated carrier cannot start itself when clear. |
| SA | Stop SA | yes | no | Predefined SA only. |
| SA | SA Status | yes | yes | Reports the last procedure tag. |
| SA | Create/Delete SA | no | no | Dynamic SA creation and deletion are unsupported. |
| Monitoring | Ping | yes | yes | Empty request/reply. |
| Monitoring | Log Status | yes | yes | Fixed-capacity volatile ring. |
| Monitoring | Dump Log | yes | yes | Fixed Event Message nested TLVs only. |
| Monitoring | Erase Log | yes | yes | Does not clear FSR or security state. |
| Monitoring | Self Test | yes | yes | Caller callback; missing callback reports not-OK. |
| Monitoring | Alarm Flag Reset | yes | no | Clears only FSR alarm/error bits. |

SA-management recipient operations address configured RX and TX SAs, subject
to role, mode, key-use, state, and authenticated-carrier checks. Reverse-path
management is therefore not a separate protocol mode: a command may manage a
predefined opposite-direction SA when those checks pass. Runtime association
changes and unconfigured SPIs remain unsupported.

| SDLS profile question | Status |
|---|---|
| Key Destruction | Unsupported. |
| Dynamic Create SA / Delete SA | Unsupported; SAs are predefined. |
| Reverse-direction SA management | Supported for a predefined opposite-direction SA when lifecycle, key-use, and authenticated-carrier checks pass. |
| User-defined procedures | Unsupported. |
| Nested TLVs | Only the fixed managed Event Message TLV in Dump Log is supported. Arbitrary nesting is rejected. |
| Resource growth | Compile-time fixed; no heap fallback or dynamic table growth. |
| Defaults | Four SAs, eight keys, eight event records; see [configuration](configuration.md). |

## Resource and verification scope

All tables, workspaces, PDUs, missing ranges, and monitoring records are fixed
at build time. Defaults are canonical in [configuration](configuration.md).
Applications may override them; those values are mission/profile facts, not
module defaults.

Native module tests cover codecs, state transitions, failure atomicity,
TM/TC integration, CFDP, SDLS vectors, and bounded behavior. The packet-level
two-peer CFDP UDP harness is verified. Full asymmetric TC-uplink/TM-downlink
CFDP validation and independent SDLS interoperability remain planned. The
ESP32-S3 PSA proof built successfully, but recorded provider inspection found
software GCM/GMAC; no on-device benchmark values were collected.

## Internal status and error values

These are developer-facing return values, not operator messages.

| CFDP status | Value | Meaning |
|---|---:|---|
| `OK` | 0 | Operation accepted/completed at this API boundary. |
| `INVALID_ARGUMENT` / `BUFFER_TOO_SMALL` / `MALFORMED_PDU` | 1 / 2 / 3 | Caller or received representation error. |
| `UNSUPPORTED` / `UNSUPPORTED_CHECKSUM` / `INVALID_TRANSMISSION_MODE` | 4 / 5 / 6 | Outside the implemented subset. |
| `CHECKSUM_FAILURE` / `FILE_SIZE_ERROR` | 7 / 8 | Received file validation failed. |
| `INACTIVITY_DETECTED` / `NAK_LIMIT_REACHED` | 9 / 10 | Bounded recovery failed. |
| `CANCEL_REQUEST` / `FILESTORE_REJECTION` / `TRANSACTION_BUSY` | 11 / 12 / 13 | Transaction or consumer boundary rejected the operation. |

| SDLS error | Value | Meaning |
|---|---:|---|
| `FORMAT` | -1000 | Malformed received representation. |
| `AUTHENTICATION` / `REPLAY` | -1001 / -1002 | Tag or receive-sequence rejection. |
| `UNKNOWN_SA` / `SA_STATE` | -1003 / -1004 | SPI or SA lifecycle/role rejection. |
| `KEY` / `KEY_STATE` | -1005 / -1008 | Key identifier, attributes, or lifecycle rejection. |
| `PSA` | -1006 | Recoverable PSA runtime failure. |
| `UNSUPPORTED` | -1007 | Procedure or operation outside the profile. |
| `CAPACITY` | -1009 | Fixed resource bound exceeded. |
