# zephyr-ccsds

`zephyr-ccsds` is a standalone Zephyr module providing reusable CCSDS packet,
routing, transfer-frame & channel-coding. It also provides:

- CFDP file transfer 
- SDLS authentication & encryption in both TM & TC using GCM&GMAC
- SDLS EP key management

It provides a UDP adapter for demo purposes.

## Why this is Interesting

`zephyr-ccsds` provides a selectively complete classic CCSDS protocol implementation targeted natively
to Zephyr RTOS, allowing deployment to extreme resource-constrained platforms such as MCU; for
example STM32-based microcontrollers are widely used in micro- and nanosatellites in low-earth-orbit.

The project is intended for spacecraft flight software, payload processors, intelligent instruments and 
ground-based simulation environments that require CCSDS communications without imposing a complete framework.

Zephyr is increasingly being adopted for embedded systems requiring a richer driver ecosystem, modern 
tooling and broader hardware support than is typically associated with traditional embedded RTOSes.
Work is underway within the Zephyr community to support safety-oriented use cases.

The implemented CCSDS subset is intentionally "traditional", i.e. it does not attempt to tunnel IP protocols
over CCSDS, uses CFDP for file transfer and SLDS & EP for security. This is with a view to interoperability 
with existing ground systems, modems, transponders and operational practices used throughout the CCSDS ecosystem. 

There is no DTN, no BPSEC. It does not (for now) support USLP, although it may be added in future.

The implementation intentionally avoids providing a complete flight software framework. Instead it provides 
reusable communications components that integrate naturally into Zephyr applications as a library. This allows missions
to design & format packet contents as they choose.

Lower-level decoding and encoding tasks are compile-time optional, since 
they may be supported by external hardware units (or deployed across multiple MCU). 
Cryptography uses the PSA API, which will use hardware assistance if available.

Obviously, the more you do in software, the lower the data rate you can support in a low-end MCU.

In comparison with CSP (widely used on cubesats), CCSDS offers more standardisation 
& safety e.g. error correction, flow control, authentication & encryption & file transfer. In CSP, the open standard protocols only cover the packet format; everything else is proprietary. 

CCSDS remains the dominant interoperability standard for institutional space missions and 
provides the broadest ecosystem of interoperable communications infrastructure currently available. The standards are openly published.

## Deployment

Zephyr applications consume it through standard module discovery and select
the required protocol components through Kconfig.

The [akira-ccsds](https://github.com/clythersHackers/akira-ccsds) project
consumes this module as a west project for its application and device
integrations. `zephyr-ccsds` is independent of AkiraOS, so other Zephyr
applications can use its CCSDS implementation without adopting AkiraOS or its
product-specific policies.

The module supplies public headers, neutral `CONFIG_CCSDS_*` Kconfig symbols,
CMake integration, tests, samples, and application-facing callback boundaries.
Applications retain ownership of endpoints, device drivers, filesystem layout,
mission policy, security policy, and lifecycle behavior.

The included UDP adapter provides a ready-to-use transport. The callback
boundaries also allow consuming applications to connect other transports,
such as serial/UART, TWAI/CAN, Bluetooth LE, or radio, without changing the
CCSDS protocol implementation. Adapters for those transports are not currently
included in this repository.

## Implemented Subset

- CCSDS Space Packet encode/decode and APID routing.
- TC transfer-frame and segment decode, complete-CLTU decode, BCH correction,
  packet reassembly.
- A single-VC spacecraft receive profile covering sequence acceptance, 
  lockout/retransmit state, UNLOCK and SET V(R), FARM-B counting, and CLCW generation.
- TM transfer-frame generation, per-VC packet queues and routes, CLCW
  insertion, optional FECF, randomization, and Reed-Solomon coding.
- CFDP PDU codecs, checksums, filestore/UT callback boundaries, Class 1
  closure, missing-range recovery.
- SDLS fixed-profile AES-256-GCM/GMAC wire processing, predefined-SA and key
  management by Extended Procedures, FSR generation.

See the [documentation index](doc/index.md) for detailed
behaviour, configuration, ownership, and limitations.

## Requirements

- A working Zephyr west workspace.
- Zephyr 4.3.0 for the currently verified configuration.
- A Zephyr-supported toolchain for the target board.
- `native_sim` and a host compiler to run the supplied tests and sample.

The repository does not vendor Zephyr or toolchains.

## Add It To A West Workspace

Add this project to the `projects` list in your application's west manifest:

```yaml
manifest:
  projects:
    - name: zephyr-ccsds
      url: https://github.com/clythersHackers/zephyr-ccsds
      revision: main
      path: modules/lib/ccsds
```

Then update only this project:

```sh
west update zephyr-ccsds
```

Using `main` is convenient while evaluating the module. Pin an immutable
commit SHA or release tag for reproducible application builds. Zephyr discovers
`zephyr/module.yml` automatically when the project is part of the active west
manifest.

### Existing Local Checkout

For temporary development outside a manifest, pass the repository's absolute
path through `ZEPHYR_EXTRA_MODULES`:

```sh
west build -b native_sim /path/to/application --pristine -- \
  -DZEPHYR_EXTRA_MODULES=/absolute/path/to/zephyr-ccsds
```

Do not combine manifest discovery and `ZEPHYR_EXTRA_MODULES` for the same
checkout; duplicate discovery can cause duplicate Kconfig or compilation
integration.

## Enable It In An Application

Once the module is discovered, an application needs no module-specific CMake
calls:

```cmake
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(my_ccsds_app)
target_sources(app PRIVATE src/main.c)
```

Enable the core in `prj.conf`:

```ini
CONFIG_CCSDS=y
```

Public headers use the `ccsds/` prefix:

```c
#include <ccsds/ccsds_space_packet.h>
#include <ccsds/ccsds_router.h>
```

Frame support is enabled by default. Enable CFDP explicitly:

```ini
CONFIG_CCSDS=y
CONFIG_CCSDS_CFDP=y
```

For a packet-only CFDP application that does not need TC/TM transfer frames or
channel coding:

```ini
CONFIG_CCSDS=y
CONFIG_CCSDS_CFDP=y
CONFIG_CCSDS_FRAME_SUPPORT=n
```

All protocol state is statically allocated or caller-owned. Review the
[module user guide](doc/user-guide/index.md) and
[configuration reference](doc/reference/configuration.md) before selecting
buffer sizes for a constrained target.

## Build And Run The Sample

From this repository's root inside a Zephyr west workspace:

```sh
west build -b native_sim samples/space_packet \
  -d build/ccsds-space-packet --pristine
./build/ccsds-space-packet/zephyr/zephyr.exe
```

Expected output includes:

```text
CCSDS Space Packet round trip OK: APID=1 sequence=42 payload=deadbeef
```

Stop the native simulator with Ctrl+C after the result is printed. See the
[sample README](samples/space_packet/README.md) for its exact behavior.

## Run Verification

From this repository's root:

```sh
west twister -T tests -p native_sim --inline-logs
west twister -T samples -p native_sim --inline-logs
tests/cfdp_udp/run_cfdp_udp_integration.sh
```

The test suites cover module discovery, primitives, frames and profiles, CFDP,
and packet-level two-peer UDP transfer with success, dropped-data recovery,
and corruption failure.

## Development In A Consuming Workspace

West normally checks pinned projects out at a detached commit. Before editing
this repository, attach it to `main`:

```sh
git fetch origin main
git switch main
git pull --ff-only
```

If the west-created checkout does not yet have a local `main` branch, create
it once with `git switch --create main --track origin/main`.

Commit and push module changes from this repository. Consumers should then
update their manifest to the resulting immutable commit SHA and rerun their
own integration matrix. A later `west update` may return the checkout to the
consumer's pinned detached revision; it does not delete the local branch.

Reusable protocol behavior, public APIs, neutral Kconfig, tests, and samples
belong here. Board configuration, concrete route policy, filesystem paths,
shell commands, product logging, artifact installation, and application
lifecycle belong in the consuming application.

## Documentation

- [Documentation index](doc/index.md)
- [Module user guide](doc/user-guide/index.md)
- [Development guide](doc/development/index.md)
- [Design documentation](doc/design/index.md)
- [Reference](doc/reference/index.md)
- [Plans](doc/plans/index.md)
- [Space Packet sample](samples/space_packet/README.md)

## License

The module is distributed under the [Apache License 2.0](LICENSE). The CCSDS
standards themselves are not distributed with this repository.
