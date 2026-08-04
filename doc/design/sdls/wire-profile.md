# SDLS wire profile

This note records the compiled SDLS wire profile and its verification
boundary. It is a design and conformance note, not a claim of complete CCSDS
355.0 or reset-safe operational security.

## Implemented wire profile

The reusable API implements the following fixed choices:

- a 14-octet Security Header containing a big-endian 16-bit SPI followed by
  the complete 96-bit IV;
- no separate Sequence Number or Pad Length field;
- a 16-octet Security Trailer containing the 128-bit authentication tag;
- AES-256-GCM authenticated encryption; and
- AES-256-GMAC constructed with PSA GCM, zero plaintext, and all protected
  frame data supplied as additional authenticated data.

These choices apply CCSDS 355.0-B-2 clauses 4.1.1.1 through 4.1.1.3 for field
order and managed field lengths and clause 4.1.2 for the trailer. The field
dimensions match the GCM baseline in annex E; using that GCM form for the
authentication-only GMAC service is a fixed choice of this project profile,
not the annex E TC/CMAC baseline. The implementation encodes each integer
explicitly and never casts wire bytes to a C structure.

SPI values zero and 65535 are rejected because clause 4.1.1.2.3 reserves
them. Codec decoders require the exact compiled length; short input and
trailing input are format errors.

The compiled implementation profile further constrains configured SPIs to the
dense range `1..CONFIG_CCSDS_SDLS_MAX_SA`. Wire SPI `n` addresses SA array
slot `n - 1`, so selection requires one range check and no search or stored
SPI. Key IDs use the dense range `0..CONFIG_CCSDS_SDLS_MAX_KEYS-1` and address
the key array directly. IDs below `CONFIG_CCSDS_SDLS_SESSION_KEY_BASE` are
master-key slots; IDs at or above the boundary are session-key slots. The
boundary is explicit so increasing the key array does not reclassify existing
keys.

## Authentication regions and masks

The API receives the contiguous transfer-frame header bytes preceding the
Security Header. Its mask is only a prefix extending through the final
zero-mask byte. Bytes after `mask_len` are implicitly masked with `0xff`; a
zero `mask_len` therefore authenticates the complete supplied header. This
keeps the common mask representation to the minimum required size instead of
storing a byte for every authenticated frame byte.

The header exposes separate compact arrays for the CCSDS 355.0-B-2 clause
4.2.2.6.2 defaults:

- `ccsds_sdls_tm_default_auth_mask` is the six-byte
  `3f fe 00 00 00 00` TM primary-header mask;
- `ccsds_sdls_tc_default_auth_mask` is the five-byte
  `03 ff fc 00 00` TC primary-header mask.

A TC Segment Header immediately following that five-octet prefix is
implicitly all-one masked, as required by the default. A mission that uses
additional header fields which the standard excludes by default extends the
compact prefix with the necessary zero bytes. Mission-specific masks may
authenticate additional fields.

The reusable primitive adds the Security Header authentication treatment
itself: the SPI is authenticated and the IV positions are retained as 12
zero-mask bytes in the Authentication Payload. In GMAC mode, the clear Frame
Data is also AAD. In GCM mode, Frame Data is the AEAD plaintext and GCM
authenticates the resulting ciphertext. Callers must provide exactly the
applicable TM or TC header bytes, in wire order, and the corresponding mission
mask. Structure padding and bytes produced after SDLS processing are not
accepted implicitly.

The [TM/TC integration design](index.md) remains responsible for selecting concrete
almost-complete-frame boundaries and the link-specific default mask required
by clause 4.2.2.6.2.

## IV and reset boundary

The 32-bit ARSN is encoded in the low four nonce octets in network byte order.
The high eight octets are an independent sender IV value, also in network byte
order. This implementation initializes that value from the compiled seed and
advances it after each attempted protected transmission:

```text
next_sender_iv = sender_iv + 0x9e3779b97f4a7c15 modulo 2^64
```

The increment is the odd 64-bit golden-ratio Weyl/Knuth constant. It
disperses consecutive sender IV values but supplies no randomness. The
compiled seed defaults to zero and can be replaced through its two Kconfig
halves. The ARSN advances independently as a sequential per-key `uint32_t`.

Transmit state is one volatile 32-bit ARSN in each key slot and one 64-bit
sender IV in the context. Applying security consumes both values before
calling PSA, including when PSA fails. There is no allocator, reservation
range, persistence callback, warning threshold, or special terminal value.
Unsigned wrap follows normal C semantics; a genuine ARSN wrap after 2^32
protected frames is treated as an operationally theoretical condition.

This deliberately small model does not make nonce uniqueness survive reset.
After a crash or power cycle, protected transmission with the old key must
not resume from a reset counter. The operational recovery policy is to install
fresh session keys by OTAR before protected transmission resumes. Persistent
counter storage, if a consumer later needs it, remains application policy and
is not represented in the reusable context.

## Receive anti-replay policy

Each receive SA stores only the last authenticated ARSN and an initialized
flag.

- The first correctly authenticated value initializes the state.
- Later values must be strictly greater than the stored value.
- A forward gap of at most `CONFIG_CCSDS_SDLS_ARSN_WINDOW` is accepted.
- A duplicate, lower value, or larger forward gap is rejected.
- All 32-bit ARSN values and all 64-bit sender IV values are valid.

Replay eligibility is checked before authentication, but the complete
12-byte nonce is authenticated by GCM and the stored ARSN changes only after
successful tag verification.
Authentication, format, capacity, and replay failures leave receive state and
clear output bytes unchanged.

This profile interprets the managed sequence-number window as the maximum
permitted forward gap. It does not retain a replay bitmap and does not accept
out-of-order lower values.

## Fixed state and storage cost

With the default four SAs, eight keys, and eight monitoring records, the
current complete caller-owned SDLS context is 272 bytes. That includes later
key/SA-management, FSR, event-ring, callback, and provenance fields in addition
to the wire-processing state described here. Compile-time and test assertions
cover the native and 32-bit target layouts. PSA provider storage and
caller-owned crypto workspaces are outside the context cost.

## Verification boundary

The `tests/sdls` native suite covers exact codec bytes and bounds,
deterministic IV vectors, GCM and GMAC round trips, mask inclusion and
exclusion, tampered tags and authenticated fields, strictly increasing replay
state, permitted gaps, natural counter wrap, direct SA/key mapping,
fixed-SA/key validation, and programmer-contract buffer assertions.

The wire codec does not modify TC/TM services, Akira integration, `west.yml`,
COP-1, routing, device I/O, or Extended Procedures.
