# TM/TC integration guide

Audience: module users integrating telemetry and telecommand paths.

Enable `CONFIG_CCSDS=y`; `CONFIG_CCSDS_FRAME_SUPPORT` defaults to `y`.
Include public headers through the `ccsds/` prefix.

## Telecommand receive

The complete-message path decodes a bounded CLTU, corrects/detects BCH block
errors, validates a version-0 TC transfer frame and configured spacecraft ID,
walks segments, reassembles bounded Space Packets, and dispatches them through
the APID router. The profile accepts one configured VC and implements the
documented bounded COP-1/FARM behavior, including UNLOCK and SET V(R). It is
not a general COP-1 implementation.

Use `ccsds_cltu_decode_message()` when the transport supplies one complete
CLTU. Incremental `ccsds_cltu_rx_push()` is currently unsupported; see the
[streaming plan](../plans/tc-streaming.md). Packet-only builds can use the
bounded input profile without frame support.

## Telemetry transmit

Initialize TM state, register route callbacks with
`ccsds_tm_frame_register_route()`, assign per-VC route masks, then start the
generator. It supports eight VCs, fixed-length frames, Space Packet
continuation, idle data on VC 7, master/VC counters, optional CLCW and FECF,
optional randomization, and Reed-Solomon encoding.

TM queues and workspaces are module-global, so one generator exists per image.
The generator selects the lowest numbered VC with pending data. Route callbacks
run from the system work queue and receive already encoded output; failures are
not retried by the generator. Concrete route policy remains application-owned.

With Reed-Solomon enabled, the TM transfer-frame body is
`223 * CONFIG_CCSDS_RS_INTERLEAVE_DEPTH` bytes and must fit
`CONFIG_CCSDS_MAX_FRAME_LEN`. Without Reed-Solomon, the configured maximum
frame length is the emitted TM frame length.

See the [TM/TC design](../design/tm-tc.md) and
[configuration reference](../reference/configuration.md) for exact contracts.

