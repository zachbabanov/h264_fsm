# Architecture

The project is split into modules:

- `server` — accepts TCP client connections, receives FEC-wrapped H.264 packets,
  decodes them (stub, pass-through), and streams decoded bytes to a per-client player (ffplay).
- `client` — connects to server and streams H.264 bytes from a file, packaging them into FEC packets.
- `player` — platform abstraction for launching ffplay (stdin) and writing bytes to it.
- `encoder` — `StubFec` provides a header format and pass-through encode/decode. API compatible with rscoder.
- `logger` — thread-safe logging with categories: GENERAL, VIDEO, FEC, PLAYER, NETWORK.

Key design choices:
- Non-blocking sockets (epoll on Linux; WSAPoll on Windows).
- Per-client finite-state machine (READING, PROCESSING, WRITING, CLOSING).
- Keep-alive via UDP register/heartbeat (client registers to server using UDP).
- Player is spawned per-client so each client has a separate playback window.
