# SDLS Stage 5 SA Management and FSR Profile

## Scope and conformance basis

This module implements the CCSDS 355.1-B-1 predefined-SA subset comprising
Start SA, Stop SA, Rekey SA, Expire SA, Set ARSN, Set ARSN Window, Read ARSN
command/reply, SA Status command/reply, and Alarm Flag Reset. Procedure tags,
the four-octet Frame Security Report (FSR), and the initial CLCW-first phase
follow the CCSDS Appendix reference implementation. Create SA, Delete SA,
runtime association changes, the security event log, and all other monitoring
procedures are unsupported.

The common three-octet header retains the Stage 4 rules: the big-endian length
counts data-field bits, must be octet aligned, and must account for the exact
PDU with no truncation or trailing data. User procedures, unknown tags,
nesting, incomplete association fields, unsupported sizes, and values beyond
the compile-time profile bounds are rejected. All objects and workspaces are
caller-owned; no heap or dynamically sized table is introduced.

## Fixed wire forms

SA Management uses service group `01`; Alarm Flag Reset uses Monitoring and
Control group `11`.

| PDU | Tag | Data field |
|---|---:|---|
| Read ARSN Command / Reply | `0x10` / `0x90` | SPI / SPI and 32-bit ARSN |
| Set ARSN Window | `0x15` | SPI and 32-bit window |
| Rekey SA | `0x16` | SPI, Key ID, and RX-only 32-bit initial ARSN |
| Expire SA | `0x19` | SPI |
| Set ARSN | `0x1a` | SPI and 32-bit ARSN |
| Start SA | `0x1b` | SPI and zero or more 32-bit GVCID/GMAP values |
| Stop SA | `0x1e` | SPI |
| SA Status Command / Reply | `0x1f` / `0x9f` | SPI / SPI and last procedure tag |
| Alarm Flag Reset | `0x37` | empty |

The constrained initiator emits Start SA with no association values. The
recipient also accepts up to `CONFIG_CCSDS_SDLS_MAX_SA` complete 32-bit values,
but ignores them because channel associations are compile-time fixed. This is
the documented zero-association extension selected by the Akira profile.

RX Rekey is eight data octets and initializes the fixed 32-bit receive ARSN.
TX Rekey is four data octets and has no ARSN field. Set ARSN and Set ARSN
Window always use four-octet big-endian values. A window must be nonzero and
no greater than `CONFIG_CCSDS_SDLS_ARSN_WINDOW`; remote procedures cannot
increase the compiled replay capacity.

## Fixed-SA lifecycle and rekey

Only configured direct-index SPIs can be addressed. Legal transitions are:

```text
Stopped --Start--> Operational --Stop--> Stopped
Stopped --Expire--> Expired --Rekey--> Stopped
```

Start requires an associated compatible Active session key. Rekey requires an
Expired target and an existing Active session-key slot. Master, empty,
Pre-Activation, Deactivated, reserved, and out-of-range keys are rejected.
The opaque PSA key must provide the operation required by the SA direction,
and another SA may not already use the slot with a different direction or
security mode. Roles, algorithms, modes, wire fields, and channel associations
never change.

Recipient code validates the complete command before mutation. RX Rekey
changes the key reference and receive replay initialization atomically. TX
Rekey changes only the SA key reference and lifecycle state; the selected key
slot's transmit ARSN and the context sender-IV allocator are preserved. Tests
exercise Stop/Expire/Rekey/Start for both the operational TC receive SA and
operational TM transmit SA without context reinitialization.

Set ARSN and Set ARSN Window accept only configured receive SAs that are not
Expired. Set ARSN cannot move initialized replay state backwards. Read ARSN
returns the operational receive value. This state remains separate from the
FSR frame sequence-number octet. The packet-service transaction API rejects a
management command that would mutate the same SA protecting its carrying
frame.

## FSR and packet-service transactions

The FSR is encoded in network byte order as:

```text
octet 0: CWT=0, version=100, Alarm, Bad SN, Bad MAC, Bad SA
octets 1-2: last relevant SPI
octet 3: low octet of the last successfully authenticated frame ARSN
```

ProcessSecurity sets Alarm and the corresponding condition for authentication
failure, stale/duplicate/excess-gap ARSN, and unknown, stopped, expired,
wrong-direction, keyless, or otherwise unusable SAs. It records the relevant
SPI without changing the last successful ARSN octet. Authentication success
clears Bad SN, Bad MAC, and Bad SA, records the successful SPI and low ARSN
octet, and commits receive replay state. Alarm remains latched until Alarm Flag
Reset.

SDLS EP is a packet service, separate from transfer-frame security. The TC
profile first reads the clear TC Segment Header, then authenticates/decrypts
the packet data using the SPI carried in the following SDLS Security Header.
The segment header, including MAP ID, is authenticated as additional data but
is not encrypted. After packet extraction, the configurable MAP ID/APID route
selects EP. `ccsds_sdls_ep_process_pdu()` receives only that packet's payload;
carrier SPI and ARSN are not part of the EP service interface.

ProcessSecurity retains the authenticated frame indication inside the SDLS
context for synchronous safety checks, but it also owns all FSR success
updates. EP recipient success or rejection does not reinterpret frame-security
acceptance. Lower-level recipient APIs remain available for local
administrative use.

Alarm Flag Reset clears only Alarm, Bad SN, Bad MAC, and Bad SA. It preserves
the last SPI/ARSN indication, operational replay state and window, SA/key
lifecycle state, PSA keys, transmit allocation state, OCF phase, and caller
outputs.

## TM OCF integration

`ccsds_sdls_fsr_set_enabled()` enables FSR reporting for the caller-owned
context used by the existing TM generator. The existing CLCW callback and
serialization remain unchanged. OCF selection is:

```text
CLCW, FSR, CLCW, FSR, ...
```

The context initializes to the CLCW-first phase. Selection uses the existing
single OCF append point, so there is no duplicate TM framing path. The phase
toggles only at successful frame completion alongside the TM frame counters.
An ApplySecurity failure or aborted construction neither emits a frame nor
advances the phase. The sequence is frame-count driven and independent of
time, VC, and packet/idle content.
