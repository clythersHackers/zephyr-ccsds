# CCSDS module user guide

Audience: developers integrating the reusable CCSDS library into a Zephyr
application.

The module implements bounded embedded subsets of CCSDS Space Packet, TM/TC,
CFDP, and SDLS. It supplies protocol code, public APIs, neutral
`CONFIG_CCSDS_*` symbols, and callback boundaries. The consuming application
owns transports beyond the supplied UDP adapter, filesystem and endpoint
policy, lifecycle, provisioning, and mission configuration.

## Guides

- [TM/TC integration](tm-tc.md)
- [CFDP integration](cfdp.md)
- [SDLS integration](sdls.md)

Use the [configuration reference](../reference/configuration.md) for Kconfig
defaults and the [supported-feature reference](../reference/supported-features.md)
for precise protocol coverage. Developers building or changing the module
should use the [development guide](../development/index.md). Implementation
structure and wire profiles are in [design](../design/index.md); unfinished
work is isolated under [plans](../plans/index.md).

## Common integration rules

- Protocol state is statically allocated, module-global where documented, or
  caller-owned. The module does not allocate protocol state from the heap.
- Decoded payload pointers are views into caller-provided buffers. Transport
  receive buffers remain valid only during their callback unless copied.
- Programmer contract violations assert; malformed wire input and recoverable
  PSA, transport, or capacity failures return errors.
- Callback boundaries carry bounded complete units and do not prescribe UDP,
  UART, radio, CAN, or another device interface.
