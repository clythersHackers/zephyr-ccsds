# CCSDS Space Packet round trip

This sample encodes a version 0 TC Space Packet, checks its deterministic wire
representation, decodes it, and verifies every field and payload byte. It uses
only the public module API and neutral configuration.

From a Zephyr workspace containing this module:

```sh
west build -b native_sim samples/space_packet \
  -d build/ccsds-space-packet
./build/ccsds-space-packet/zephyr/zephyr.exe
```

Expected output includes:

```text
CCSDS Space Packet round trip OK: APID=1 sequence=42 payload=deadbeef
```

Stop the native simulator with Ctrl+C after the result is printed. Encoding or
decoding failures print a failure line instead. The successful result can also
be verified automatically with:

```sh
west twister -T samples -p native_sim --inline-logs
```
