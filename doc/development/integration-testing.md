# Integration testing

Audience: developers running multi-process or consuming-application tests.

Run the two-peer packet-level CFDP UDP test from the module root:

```sh
tests/cfdp_udp/run_cfdp_udp_integration.sh
```

It builds reciprocal `native_sim` peers and verifies intact acknowledged
transfer, one dropped segment recovered by NAK/retransmission, and corruption
failure without committing the destination. Each UDP datagram contains one
encoded Space Packet; the harness does not exercise TC/CLTU uplink or TM/CADU
downlink. That boundary is tracked in the
[full-link plan](../plans/cfdp-full-link-validation.md).

Consuming repositories should separately verify their endpoints, storage,
routing, startup, mission configuration, and target board.

