# Building the module

Audience: module developers and integrators verifying Zephyr discovery.

The currently verified workspace uses Zephyr 4.3.0. Add this repository as a
west project or pass its absolute path through `ZEPHYR_EXTRA_MODULES`; do not
use both discovery methods for the same checkout.

Build the deterministic sample from the module root in a Zephyr workspace:

```sh
west build -b native_sim samples/space_packet \
  -d build/ccsds-space-packet --pristine
./build/ccsds-space-packet/zephyr/zephyr.exe
```

Expected output includes:

```text
CCSDS Space Packet round trip OK: APID=1 sequence=42 payload=deadbeef
```

Sample-specific details remain in
[`samples/space_packet/README.md`](../../samples/space_packet/README.md).

