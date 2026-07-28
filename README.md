# CCSDS Zephyr module

This module provides reusable CCSDS packet, routing, transfer-frame,
channel-coding, UDP adaptation, and CFDP components for Zephyr applications.

- [User guide](doc/index.md)
- [Space Packet round-trip sample](samples/space_packet/README.md)
- Module tests: `west twister -T modules/ccsds/tests -p native_sim --inline-logs`
- Samples: `west twister -T modules/ccsds/samples -p native_sim --inline-logs`

The module contains protocol implementations and application-facing callback
boundaries. Endpoint selection, filesystem layout, mission policy, and product
behavior remain the responsibility of the consuming application.
