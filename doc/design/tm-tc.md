# TM/TC design

Audience: developers modifying TM/TC packet, frame, coding, or routing code.

## Ownership and data flow

Space Packet and TC decoders expose views into caller buffers. The APID router
is caller-owned and fixed-capacity. Each TC receive profile owns its maximum
frame and reassembly buffers. TM queues and frame workspaces are module-global
and fixed at build time.

```text
bounded input -> CLTU/BCH -> TC frame -> COP-1/FARM -> segment/reassembly
              -> Space Packet -> APID router

Space Packet -> per-VC queue -> TM frame -> OCF/FECF -> randomization/RS
             -> selected route callbacks
```

Transport adapters terminate at bounded-unit callbacks. Device discovery,
endpoint selection, route names, and retry policy do not enter the frame code.

## Design constraints

- TC accepts complete CLTUs; streaming acquisition is a planned extension.
- The receive profile is deliberately one-VC and implements a bounded COP-1
  subset rather than a general procedure engine.
- TM uses fixed-length frames and one generator per image.
- Reed-Solomon encoding is implemented; decoding is not.
- Optional SDLS processing occurs at the almost-complete-frame boundaries
  described in [SDLS design](sdls/index.md).

