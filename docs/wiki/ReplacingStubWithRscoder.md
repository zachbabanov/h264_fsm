# Replacing StubFec with rscoder

1. Study rscoder API: rscoder encodes/decodes symbols. Map our API:
   - `encode_with_header` -> prepare data symbols, call rscoder encode to produce parity symbols,
     then store result as `encoded_payload`.
   - `decode_payload` -> feed received symbols to rscoder decoder, attempt reconstruction.

2. Implementation steps:
   - Add rscoder C++ sources or link library (update CMakeLists).
   - Implement in `src/encoder.cpp`:
     - In `encode_with_header`, split data into `k` symbols of proper symbol size (padding last symbol).
     - Call rscoder to generate `m` parity symbols, append them and produce a framing that server can parse.
     - Update `FecPacketHeader.payload_len` to real encoded bytes length.
   - In `decode_packet`, parse header & extract encoded bytes, feed into rscoder decoder and retrieve reconstructed bytes.

3. Logging:
   - Use `LOG_FEC_*` to report encoded size, parity overhead, and decode success/failures for experiments.
