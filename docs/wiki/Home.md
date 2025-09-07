# Project Wiki - Home

This lightweight wiki describes the project's design, protocol, and how to replace the stub FEC encoder
with a real Reed–Solomon implementation (example: `zachbabanov/rscoder`).

Sections:
- Architecture.md — overall component architecture.
- Protocol.md — wire protocol including UDP control header and FEC packet header.
- ReplacingStubWithRscoder.md — step-by-step guide to integrating `rscoder`.
- QoS_and_Logging.md — details about collected QoS metrics and where to find them in logs.
