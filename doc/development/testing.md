# Testing the module

Audience: developers verifying changes to the reusable implementation.

Run from the module repository root:

```sh
west twister -T tests -p native_sim --inline-logs
west twister -T samples -p native_sim --inline-logs
```

The suites cover module discovery, packet/routing primitives, TM/TC frames and
profiles, channel coding, CFDP, SDLS wire processing, Extended Procedures,
state transitions, capacity/error paths, and samples. Test success establishes
the module path on `native_sim`; it does not by itself establish independent
interoperability or mission hardware-link verification.

