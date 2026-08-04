# CFDP integration guide

Audience: module users integrating the reusable CFDP service.

Enable `CONFIG_CCSDS_CFDP=y` and provide two application boundaries:

1. `struct ccsds_cfdp_filestore_ops` for bounded file access, temporary-file
   commit, and discard. Paths and handles are application-owned.
2. `struct ccsds_cfdp_ut_ops` for PDU transmission and monotonic time.

The entity supports one active sender and one active receiver. It is
synchronous and creates no thread; serialize access to an entity/service and
poll often enough to service recovery deadlines. The current retry interval is
1000 ms, with recovery bounded by `CONFIG_CCSDS_CFDP_MAX_NAK_ROUNDS`.

`struct ccsds_cfdp_space_packet_adapter` maps one CFDP PDU to one complete
Space Packet and registers its APID with a caller-owned router.
`struct ccsds_cfdp_service` composes the entity and adapter. Multiple services
have independent transaction and packet-sequence state, while routers,
filestores, callbacks, and callback contexts remain caller-owned.

The supported subset covers small-file acknowledged and unacknowledged
transfer, closure, missing-range recovery, and the checksums listed in the
[support matrix](../reference/supported-features.md). Filesystem layout,
artifact interpretation, activation, and rollback are consumer policy.

Use the [integration test guide](../development/integration-testing.md) for
the two-peer UDP harness. Full asymmetric-link validation remains in the
[CFDP full-link plan](../plans/cfdp-full-link-validation.md).

