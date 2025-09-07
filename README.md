# H264 FEC Streaming Demo

A small experimental project demonstrating a client/server H.264 streaming pipeline with a pluggable FEC encoder (stubbed), non-blocking sockets and per-client player.

**Features**
- Non-blocking TCP streaming (epoll on Linux; WSAPoll on Windows).
- FEC packet framing: header + payload, compatible with future Reed–Solomon integration.
- StubFec pass-through encoder now with header framing and logs for QoS experiments.
- Per-client ffplay player process; on Windows the player writer uses a dedicated writer thread.
- UDP control channel for register/heartbeat/broadcast.
- Structured, thread-safe logging with categories (`VIDEO`, `FEC`, `PLAYER`, `NETWORK`) and timestamps (microseconds).

## Project structure

```
include/ - public headers
src/ - implementation
tests/ - unit tests (Catch2)
docs/wiki/ - documentation pages (architecture, protocol, QoS)
main_server.cpp - server entry point
main_client.cpp - client entry point
```

## Building (Linux)
Requires CMake and a C++17 compiler.

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

This produces two binaries: server and client.

## Running

### Server

```bash
./server 9000 ./ffplay server.log
```

* `9000` — TCP port.
* `./ffplay` — optional path to ffplay.
* `server.log` — optional log file.

### Client

```bash
./client 127.0.0.1:9000 sample.h264 0 client.log
```

* `127.0.0.1:9000` — server address.
* `sample.h264` — input file (raw H.264 byte stream).
* `0` — loop (use 1 to loop).
* `client.log` — optional logfile.

## Logging & QoS

Logs are sent to stdout and (optionally) to file. Use `LOG_FEC_*` and `LOG_VIDEO_*` entries to compute:

* packet overhead,
* bytes per second,
* decode success rates,
* buffer drops/hard-closes.

## Integrating rscoder (next step)

See `docs/wiki/ReplacingStubWithRscoder.md` for step-by-step guide to replace `StubFec` with `rscoder`. Key points:

* Keep `FecPacketHeader` compatible.
* Use `fec_k`/`fec_m` fields for RS parameters.
* Update `payload_len` appropriately.

## Tests

If `tests/` folder exists (it does), CMake will add the test target and fetch Catch2 to run unit tests:

```bash
cd build
ctest --output-on-failure
```

## Notes and Limitations

* The current FEC implementation is *pass-through* — it does not add redundancy.
* The framing design allows replacing the encoder with a real RS encoder without changing the server's framing logic.
* Player process is per-client; for many clients this will spawn many ffplay instances.

