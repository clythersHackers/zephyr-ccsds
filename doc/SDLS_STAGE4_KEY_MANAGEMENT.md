# SDLS Stage 4 Key Management Profile

## Scope and conformance basis

This module implements the CCSDS 355.1-B-1 Key Management subset comprising
OTAR, Key Activation, Key Deactivation, and Key Verification command/reply.
The common PDU header follows 5.3 and the procedure identifiers follow table
5-1. Field sizes and algorithms follow the baseline implementation in annex D.
Key Destruction, Key Inventory, every SA Management procedure, monitoring and
control, and user-defined procedures are unsupported.

The three-octet PDU header is an 8-bit tag followed by a big-endian 16-bit
length. The length is the number of **bits** in the data field, must be a
multiple of eight, and must exactly account for the received PDU. The profile
accepts only CCSDS Key Management tags 0x01 through 0x04 for commands and 0x84
for the Key Verification reply. It rejects user-defined tags, other service
groups, nesting, unknown or unsupported procedures, inconsistent lengths,
truncation, capacity overflow, and trailing octets.

All multioctet integers use network byte order through Zephyr byte-order
helpers. Encoded PDUs, decoded objects, and cryptographic workspaces remain
caller-owned and compile-time bounded. No heap or module-global workspace is
used.

## Fixed encodings

The selected encodings are:

| PDU | Tag | Repeated data-field entry |
|---|---:|---|
| OTAR Command | `0x01` | encrypted 16-bit Key ID and 256-bit key |
| Key Activation Command | `0x02` | 16-bit Key ID |
| Key Deactivation Command | `0x03` | 16-bit Key ID |
| Key Verification Command | `0x04` | 16-bit Key ID and 128-bit challenge |
| Key Verification Reply | `0x84` | 16-bit Key ID, 96-bit IV, 128-bit encrypted challenge, and 128-bit tag |

An OTAR data field contains a 16-bit master Key ID, 96-bit IV, one or more
34-octet encrypted key blocks, and a 16-octet tag. AES-256-GCM provides
authenticated encryption. This constrained profile additionally authenticates
the complete EP header and clear master Key ID as additional authenticated
data; the transmitted IV is the GCM nonce. Header, length, master identifier,
IV, ciphertext, and tag changes therefore cannot lead to key installation.

For the default four-master/four-session configuration the bounds are 169
octets for OTAR, 19 octets for Activation/Deactivation, 147 octets for a
Verification command, 371 octets for its reply, and 136 octets for plaintext
OTAR staging. The public macros derive these values from the configured fixed
key capacity and compile-time assertions keep bit lengths representable.

Annex D's verification interoperability profile reserves Key IDs 0 through
127 from session-key use. The existing compact Akira profile instead retains
its direct-index boundary, `CONFIG_CCSDS_SDLS_SESSION_KEY_BASE` (default 4),
because the complete table defaults to eight entries. This is a deliberate
resource-profile restriction and requires peers to use the same managed Key ID
range.

## OTAR transaction and PSA boundary

Only a present, Active master slot below the configured session-key boundary
may authenticate an OTAR. Its opaque PSA key must be a 256-bit AES key with GCM
and decrypt usage. Decrypted entries may address only empty direct-index
session slots. Master destinations, out-of-range IDs, duplicates, occupied or
deactivated destinations, non-256-bit material, and excess entries are
rejected.

Recipient processing authenticates and decrypts the entire key block before
validating a destination or importing a key. It then validates every entry
before the first import. Each successful import uses volatile PSA AES-256-GCM
attributes and produces only an opaque PSA identifier. Metadata is committed
only after every import succeeds. If a later import fails, every PSA key
created earlier in that operation is destroyed and no key-table entry changes.

Successful keys enter Pre-Activation with transmit ARSN zero. Plaintext key
blocks, decoded OTAR staging, temporary PSA identifiers, and the full supplied
workspace are explicitly wiped on every return path. The module never logs
key material, OTAR IVs, tags, challenges, ciphertext, or decrypted content.
The default PSA lifetime is volatile, so Stage 4 adds no persistent key-storage
consumption. Provisioning and persistence policy remain application-owned.

## Lifecycle and verification

Activation permits only a present, compatible session key in Pre-Activation
and changes it to Active. Deactivation permits Active or Pre-Activation and
changes it to Deactivated. Master, missing, incompatible, duplicate, and
illegal-state recipients are rejected. Every recipient is validated before
any state is changed, making a multi-key lifecycle command atomic. Repeated
Activation or Deactivation is an error. ApplySecurity and ProcessSecurity
continue to require Active keys, so Pre-Activation and Deactivated keys remain
unusable for operational frame security.

Verification is permitted for Pre-Activation or Active session keys. The
recipient encrypts each 128-bit challenge with that opaque key using AES-GCM
and returns the Appendix D IV/ciphertext/tag tuple. IVs use the existing full
96-bit sender-IV/ARSN construction. A successful reply consumes one transmit
ARSN and one sender-IV value per verified key. The checking peer decrypts and
compares the challenge without exporting key bytes. A malformed command,
invalid recipient, authentication failure, or PSA failure leaves key/SA/replay
metadata and caller output unchanged; all caller workspaces are wiped.

An SA may be initialized as already associated with an empty predefined
session slot. It remains unusable until OTAR fills the slot and Activation
makes the key Active. This supports rollover without SA creation, deletion, or
Rekey and without rebooting.

## Deliberate restrictions

- Key slots are direct-indexed and only empty session slots accept OTAR;
  replacing an occupied or Deactivated slot requires application policy.
- Algorithms, key size, IV size, tag size, challenge size, and integer widths
  are fixed to annex D; there is no algorithm identifier or negotiation.
- Key Destruction and Key Inventory are not implemented.
- No SA Extended Procedure, including Create, Delete, Start, Stop, Rekey, or
  Expire, is implemented in Stage 4.
- There is no persistent key recovery, transport, shell, provisioning policy,
  or claim of general CCSDS 355.1 conformance.
