# SDLS and Extended Procedures Plan

## Status

The module provides bounded TC receive and TM generation paths, the
transport-independent Stage 2 SDLS wire primitives described in
`SDLS_STAGE2_WIRE.md`, and the configured Stage 3 TC/TM integration described
in `SDLS_STAGE3_INTEGRATION.md`. SDLS Extended Procedures remain later stages.

This plan adds a deliberately small, statically allocated SDLS profile. It
covers the core protocol and the minimum EP key and SA operations needed to
provision, rotate, and exercise operational keys. It is not a plan for every
algorithm, link protocol, or Extended Procedure.

## Goal

Provide reusable, transport-independent SDLS processing for the existing TC
and TM paths, including authenticated over-the-air session-key upload and
bounded management of preconfigured SAs.

The implementation must:

- use only fixed-size, caller-owned or statically allocated state;
- use the PSA Crypto API and opaque PSA key identifiers;
- support only the AES-GCM family;
- permit key rollover without creating SAs at runtime;
- leave provisioning, persistence, device policy, and mission configuration
  to the consuming application; and
- preserve existing TC/TM behavior when SDLS is disabled.

## Standards Profile

Use these documents as the normative design references:

- CCSDS 355.0-B-2, Space Data Link Security Protocol;
- CCSDS 355.1-B-1, Space Data Link Security Protocol--Extended Procedures;
- CCSDS 352.0-B-2, CCSDS Cryptographic Algorithms;
- the applicable TC and TM Space Data Link Protocol standards.

Do not commit the standards or substantial copied standard text. Record
implemented options and clause references in original wording.

### Supported Cryptography

The initial profile supports:

- AES-256-GCM for authenticated encryption;
- AES-256-GMAC for authentication-only processing; and
- AES-256-GCM for authenticated encryption of OTAR key blocks.

GMAC must be implemented through a correct PSA GCM operation with no encrypted
plaintext and with the authenticated frame regions supplied as additional
authenticated data. Do not add a separate custom GMAC implementation.

The initial profile uses:

- 256-bit AES keys;
- 96-bit GCM initialization vectors (IVs); and
- 128-bit authentication tags.

No AES-CMAC, AES-CTR, HMAC, agency-specific algorithm, runtime algorithm
selection, or algorithm identifier is included. The calling TC/TM processing
path determines whether GMAC or GCM is used; the AES-256-GCM family and its
parameters are fixed by the compiled profile.

### Link Profile

The first operational paths are:

- TC reception using authentication-only AES-256-GMAC;
- TM transmission using AES-256-GCM authenticated encryption;
- EP command reception over an authenticated or authenticated-encrypted SDLS
  channel; and
- EP replies over an authenticated or authenticated-encrypted SDLS channel.

AOS and USLP are not included.

Each configured channel has exactly one of three processing modes:

- clear, with no SDLS security header or trailer;
- authenticated with AES-256-GMAC; or
- authenticated and encrypted with AES-256-GCM.

For TC, these modes apply to Type-D data frames. Standard Type-BC control
frames, including UNLOCK and SET V(R), carry neither an SDLS Security Header
nor Security Trailer and remain outside SDLS processing.

The SPI in a protected frame selects the static SA. No separate algorithm or
cipher-suite identifier is needed.

## Fixed Resource Model

Add bounded Kconfig limits with small defaults:

```text
CONFIG_CCSDS_SDLS_MAX_SA=4
CONFIG_CCSDS_SDLS_MAX_KEYS=8
CONFIG_CCSDS_SDLS_SESSION_KEY_BASE=4
```

Four SA slots allow a minimal bidirectional profile consisting of two
preconfigured EP/control SAs and two operational traffic SAs. Compile-time
configuration assigns each role its SPI and initial state. Reserved EP SPIs do
not authorize implicit unprotected traffic.

Eight key slots allow pre-provisioned master keys, active session keys for the
fixed SAs, and pre-active rollover keys. Key IDs address the array directly;
the configurable session-key boundary divides the master and session ranges.
The module maps each slot to an opaque PSA key identifier and lifecycle state.
It does not retain operational key bytes in its SA or key tables.

The limits remain configurable so applications can reduce or increase them
without changing the APIs. All operations must reject exhaustion cleanly; no
heap fallback is permitted.

### Static Security Associations

There is no general SA descriptor. Compile-time configuration defines four
fixed roles:

- EP command receive;
- EP reply transmit;
- operational TC receive; and
- operational TM transmit.

Each role has one configured SPI. The calling role fixes the direction, link
type, GMAC/GCM operation, authentication profile, 14-octet security header,
and 16-octet security trailer. These values are not repeated in each SA slot.

An SA slot contains only mutable protocol state:

- operational or stopped/expired state;
- current key-slot reference; and
- receive anti-replay state for receive roles.

PSA key identifiers remain only in the key table. Security counters and the
latest FSR status remain in the SDLS context rather than being duplicated in
every SA.

EP may start, stop, expire, or rekey one of these predefined entries. It may
not allocate an SA, delete an SA, change the table size, or introduce an
unconfigured SPI. Transfer-frame version, spacecraft ID, VCID, and MAP ID are
not stored in the SA.

A standard Start SA command carries one or more 32-bit GVCID/GMAP fields. This
profile permits zero or more such fields because channel associations are
static. The bounded recipient validates that any fields present are complete
32-bit values, ignores their contents, and changes state only for the
predefined SA named by SPI. The constrained initiator emits the zero-count
form by default, so the PDU data field contains only the SPI. Accepting and
emitting this form is an intentional extension from the standard and must be
recorded in the implementation's conformance statement.

Outbound TC/TM channel configuration selects either clear processing or a
predefined SPI. Inbound protected frames select the SA solely by SPI.

Dynamic Create SA and Delete SA procedures are unsupported.

### Fixed Key Slots

Key slots have fixed storage and mutable contents. Each slot records:

- 16-bit SDLS key ID;
- master-key or session-key role;
- lifecycle state;
- opaque PSA key identifier and attributes; and
- transmit-IV allocation state for keys permitted to transmit.

OTAR imports authenticated session-key material into an available predefined
slot, transitions it to Pre-Activation, and wipes all plaintext staging
buffers. Activation, deactivation, verification, and rekey operations only
reference existing slots.

Master keys are provisioned out of band and cannot be replaced by OTAR in the
initial profile. The module never logs keys, plaintext key blocks, tags, IVs,
or decrypted frame contents.

## PSA Crypto Boundary

Use PSA Crypto directly for AES-GCM/GMAC operations and key import/use. This
provides a portable API that can use software, platform drivers, secure
services, or hardware acceleration according to the selected PSA provider.

PSA use does not by itself prove that a target accelerates a particular
operation. Verification must inspect the resolved ESP32-S3 build
configuration and measure or otherwise demonstrate which AES-GCM/GMAC path is
selected. The module must remain correct when the PSA provider falls back to
software.

Application policy owns:

- initial master-key provisioning;
- persistent versus volatile PSA key lifetime;
- PSA key identifier ranges and storage locations;
- recovery after reset or interrupted key update;
- authorization to enable EP processing; and
- destruction or replacement of persistent key material.

The reusable module owns validation of PSA attributes required by the
configured SDLS operation and translation of PSA failures into bounded SDLS
errors without exposing sensitive details.

## IV and Replay Safety

GCM and GMAC both require IV uniqueness for a given key. This is a protocol
correctness requirement, not an optional persistence optimization. The
initial profile does not generate random IVs.

Construct the 96-bit IV from an independent 64-bit sender IV and a 32-bit
monotonic ARSN:

```text
IV[95:32] = sender_iv
IV[31:0]  = ARSN
next_sender_iv = sender_iv + iv_stride modulo 2^64
```

`iv_seed` and the odd `iv_stride` are fixed compile-time profile values. The
default stride should be a documented 64-bit Knuth/Weyl constant. This makes
the upper 64 bits change with wide numerical dispersion. It is deterministic
and predictable; it is not a cryptographic random-number generator, and
security must not depend on its apparent randomness.

ARSN is an unsigned 32-bit anti-replay sequence number. The volatile transmit
counter belongs to the key slot so moving a key reference between predefined
SAs cannot restart its sequence during one running context. The complete 12-byte
value, including both the dispersed upper field and ARSN, must be passed as
the `nonce`/IV argument to the PSA GCM operation. It is not sufficient to
place the ARSN in the Security Header or additional authenticated data while
passing a static IV to PSA.

The counter advances once per attempted protected transmission, including a
PSA failure. There is no allocator, reservation range, warning threshold, or
terminal-value check. Wrap after 2^32 messages is accepted as a theoretical
operational condition; keys are expected to be replaced by OTAR long before
that point.

The full 96-bit IV is transmitted in the Security Header. Its low 32-bit ARSN
serves as the anti-replay sequence value; this profile does not transmit a
separate Sequence Number field.

The module does not persist or reserve counter ranges. After reset or crash,
the operational recovery policy is to install fresh session keys by OTAR
before protected transmission resumes. This avoids representing a theoretical
nonvolatile allocation scheme in the small reusable context.

The design must:

- keep one volatile transmit ARSN per transmitting key slot;
- keep receive anti-replay state per SA;
- never advance receive state until authentication succeeds;
- authenticate the complete received IV while using only its low 32-bit ARSN
  for replay processing;
- consume a transmit ARSN even when PSA processing fails;
- prevent one key from being used concurrently by incompatible SAs or
  directions unless the configuration explicitly proves safe separation; and
- require a fresh OTAR session key after reset before protected transmission
  resumes.

## Architecture

### Core Objects

Add a caller-owned SDLS context containing:

- an inline fixed key array;
- an inline fixed SA array;
- SDLS apply/process context;
- EP codec and recipient/initiator state; and
- Frame Security Report (FSR) state.

The arrays are embedded directly in the context and sized at compile time by
the Kconfig limits. The application allocates the complete context statically;
initialization never accepts a dynamically sized table. Functions assert
programmer contract violations and return errors for malformed frames,
authentication failure, replay, unknown SPI/key ID, unsupported procedure,
resource exhaustion, and PSA runtime failure.

### Frame Processing Order

TM transmit processing:

```text
packet admission
-> partial TM frame construction
-> SDLS ApplySecurity
-> OCF/FSR or CLCW insertion
-> FECF
-> randomization/Reed-Solomon
-> route callback
```

TC receive processing:

```text
CLTU/channel decode
-> TC primary-header validation
-> SDLS ProcessSecurity
-> COP-1/FARM sequence handling
-> TC segment parsing/reassembly
-> APID routing
```

Authentication failure, replay failure, unknown SPI, or invalid SA state must
prevent COP-1 acceptance and packet dispatch. COP management frames that are
outside the supported SDLS service remain governed by the applicable TC/SDLS
rules rather than being forced through an operational SA.

### Frame API Changes

Refactor the frame internals only enough to expose the required
almost-complete-frame boundaries:

- TM must reserve fixed security-header/trailer space before filling the data
  field and must call SDLS before OCF/FECF/channel coding.
- TC decode must expose the primary header and secured region separately so
  SDLS can select an SA, authenticate/decrypt, and return the clear frame-data
  view.
- Existing public behavior remains available when `CONFIG_CCSDS_SDLS=n`.

Do not move transport, device, shell, or mission policy into these APIs.

## Extended Procedures Subset

### Common PDU Codec

Implement a bounded EP TLV header codec and codecs for only the selected
procedures. Reject nesting, unknown CCSDS procedures, oversized values,
trailing bytes, inconsistent lengths, and unsupported user-defined
procedures.

### Key Management

Implement:

- OTAR command encode/decode and recipient processing;
- Key Activation;
- Key Deactivation;
- Key Verification command/reply; and
- a bounded Key Inventory query/reply if required by the selected conformance
  statement.

OTAR supports at most the number of free fixed key slots, never the much
larger maximum illustrated by the standard's baseline profile. The complete
OTAR PDU and plaintext key block must fit fixed workspaces.

Do not implement key destruction in the initial reusable subset. Application
key-storage policy may explicitly destroy a PSA key through a separate local
administrative operation.

### SA Management

Implement for predefined SAs:

- Start SA;
- Stop SA;
- Rekey SA;
- Expire SA;
- Set ARSN;
- Set anti-replay window;
- Read ARSN; and
- SA status request/reply if it can be included without additional dynamic
  state.

Do not implement Create SA or Delete SA. Rekey changes only key and
receive ARSN state on a predefined SA after all state and usage checks
succeed. Transmit IV allocation continues from the selected key slot's
reserved range.

### Monitoring

Implement the four-byte FSR and expose it through an OCF provider compatible
with the existing TM generator. Support reporting at least:

- alarm state;
- bad sequence number;
- bad authentication tag;
- bad or unknown SA;
- last SPI; and
- low bits of the last received sequence value.

Support Alarm Flag Reset. Defer the security event log, log dump/erase,
self-test procedure, and other monitoring commands unless needed by the
selected conformance statement. Existing CLCW reporting must remain available;
any FSR/CLCW alternation policy belongs in the reusable profile only if it is
fully deterministic and tested.

## Implementation Stages

### Stage 1: Fixed State and PSA Proof

- Add Kconfig and caller-owned key/SA tables.
- Add compile-time size assertions and memory-footprint tests.
- Prove PSA AES-256-GCM encrypt/decrypt and GMAC-style authenticate/verify on
  `native_sim`.
- Build the same proof for `akiraconsole_esp32s3_procpu`.
- Record whether the resolved ESP32-S3 provider actually accelerates the
  selected operations.

### Stage 2: SDLS Wire Processing

- Add security-header/trailer codecs.
- Add fixed-SA lookup and validation.
- Implement ApplySecurity and ProcessSecurity using PSA.
- Add IV, anti-replay, authentication-mask, and error-path tests.
- Keep the primitives independent of TM/TC global services.

### Stage 3: TC and TM Integration

Completed by the fixed integration profile in `SDLS_STAGE3_INTEGRATION.md`:

- SDLS processing is inserted at the specified frame-processing points.
- One GMAC TC receive path and one GCM TM transmit path are configurable.
- The SDLS-disabled legacy paths remain unchanged.
- End-to-end integration tests cover delivery, tampering, replay, excessive
  gaps, SA/key failures, unknown SPI, and wrong keys.

### Stage 4: EP Key Management

- Add bounded EP codecs.
- Implement OTAR into fixed key slots.
- Implement key activation, deactivation, and verification.
- Demonstrate upload, verification, activation, and operational use of a new
  session key without rebooting.

### Stage 5: EP SA Management and FSR

- Implement the selected predefined-SA procedures.
- Implement FSR generation and TM OCF integration.
- Demonstrate rekey of fixed TC and TM SAs.
- Demonstrate that unsupported Create/Delete SA commands cannot mutate state.

### Stage 6: Akira Integration

In the consuming application:

- provide master-key and persistent PSA key provisioning;
- configure the fixed four-SA/eight-key mission profile;
- enforce fresh session-key OTAR after reset before protected transmission;
- connect TC receive and TM transmit services;
- add narrowly scoped diagnostics without revealing secrets; and
- verify with `./build.sh -b akiraconsole --ccsds`.

Keep this integration and its west manifest update in the Akira repository,
separate from reusable module commits.

## Verification

Module verification must cover:

- published AES-GCM known-answer vectors through PSA;
- GMAC known-answer vectors through the selected PSA construction;
- deterministic IV-construction vectors, including ARSN boundaries;
- security-header/trailer round trips and bounds;
- correct authenticated regions for TC and TM;
- ciphertext and tag tampering;
- duplicate, stale, permitted-gap, excessive-gap, and natural-wrap sequence
  values;
- unknown, stopped, expired, and role-mismatched SAs;
- unknown, inactive, and wrong-role key slots;
- OTAR authentication failure with no partial key import;
- atomic multi-key OTAR failure behavior;
- activation/deactivation/rekey state transitions;
- plaintext staging-buffer zeroization;
- reset and fresh-key recovery behavior;
- FSR flag and last-value behavior;
- unchanged non-SDLS TC/TM tests; and
- full-link transfer with SDLS enabled once the inverse TC/TM harness exists.

Run:

```sh
west twister -T tests -p native_sim --inline-logs
west twister -T samples -p native_sim --inline-logs
tests/cfdp_udp/run_cfdp_udp_integration.sh
```

Add focused SDLS/EP suites and the ESP32-S3 integration build to this list as
they land.

## Acceptance Criteria

- TC GMAC rejects modified, replayed, unknown-SA, and wrong-key frames before
  COP-1 state or packet dispatch changes.
- TM GCM output decrypts and authenticates with an independent peer using the
  configured fixed SA.
- OTAR imports a new AES-256 session key into a free fixed slot only after GCM
  authentication succeeds.
- A newly uploaded key can be verified, activated, and assigned through Rekey
  SA without dynamic allocation.
- No runtime command can create or delete an SA.
- No GCM/GMAC IV is reused with the same key, including across the tested
  reset model.
- PSA key material is not retained in SA metadata or emitted through logs and
  diagnostics.
- The configured four-SA/eight-key profile has a documented static RAM and
  persistent-storage cost.
- Existing non-SDLS behavior and tests remain compatible.
- AkiraOS builds for `akiraconsole_esp32s3_procpu` with SDLS enabled.

## Non-Goals

- Runtime SA creation or deletion.
- Dynamic memory allocation.
- Algorithms other than AES-256-GCM and AES-256-GMAC.
- AOS or USLP.
- General-purpose cryptographic or key-management frameworks.
- Mission-independent master-key provisioning.
- Shell-based entry or display of secret key material.
- Claiming complete CCSDS 355.1 conformance without a completed PICS and
  independent interoperability evidence.

## Consumer Responsibilities

Consumers own:

- master-key injection and trust anchor policy;
- persistent PSA storage, key locations, and device-specific protection;
- IV/ARSN persistence and power-loss recovery;
- compile-time SPI roles, clear/protected channel selection, key-ID, and route
  assignments;
- authorization and transport of EP commands;
- operational response to authentication alarms;
- shell and diagnostic presentation;
- board configuration and hardware-acceleration selection; and
- mission rollover, recovery, and compromise procedures.
