# SDLS integration guide

Audience: module users integrating the reusable SDLS profile.

Enable `CONFIG_CCSDS_SDLS=y`, include `<ccsds/ccsds_sdls.h>`, allocate a
caller-owned `struct ccsds_sdls_ctx`, and initialize predefined SAs and opaque
PSA key references. The module never retains operational key bytes and does
not own provisioning, persistent storage, transport, or recovery policy.

The fixed wire profile provides AES-256-GCM authenticated encryption and
AES-256-GMAC authentication-only processing through PSA, a 96-bit IV, a
128-bit tag, deterministic transmit allocation, and strictly increasing
receive ARSN checking with a bounded forward gap. After reset, a consumer must
not resume protected transmission with an old key and reset counters; install
fresh session keys according to mission policy.

Protected TC data is authenticated before COP-1 state or packet dispatch
changes. Type-BC control frames remain outside SDLS. TM security is applied
before OCF/FECF and channel coding. Clear SAs are predefined, keyless, and
admitted only through caller-controlled channel policy.

The Extended Procedures subset supports bounded key management, predefined-SA
management, Frame Security Report generation, and monitoring/control. Dynamic
SA creation/deletion, Key Destruction, user-defined procedures, and arbitrary
nested TLVs are unsupported. Exact direction and reply restrictions are in
the [support matrix](../reference/supported-features.md).

See the [SDLS design](../design/sdls/index.md) for wire and state-machine
details. A consuming mission must define SPI/channel assignments, trust-anchor
injection, EP authorization, persistence, reset recovery, rollover, alarms,
and any board-specific Self Test callback.

