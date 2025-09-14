/*
* @license
* (C) zachbabanov
*
*/

#ifndef PROJECT_ENCODER_HPP
#define PROJECT_ENCODER_HPP

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace project::fec {

/**
 * @brief Header prepended to each encoded FEC packet.
 *
 * Fields are stored on the wire in network byte order.
 *
 * Layout (packed):
 *   uint32_t client_id;
 *   uint32_t packet_seq;
 *   uint16_t fec_k;
 *   uint16_t fec_m;
 *   uint16_t flags;
 *   uint16_t fragments;   // number of encoded fragments in payload
 *   uint32_t payload_len; // length of encoded payload in bytes (fragments * FRAGMENT_SIZE)
 *   uint32_t orig_len;    // original (pre-encoded) payload length in bytes
 *   uint64_t pts;         // presentation timestamp in milliseconds
 */
#pragma pack(push,1)
    struct FecPacketHeader {
        uint32_t client_id;   // client identifier
        uint32_t packet_seq;  // packet sequence number
        uint16_t fec_k;       // data symbols (for RS)
        uint16_t fec_m;       // parity symbols (for RS)
        uint16_t flags;       // reserved flags
        uint16_t fragments;   // number of fragments
        uint32_t payload_len; // length of encoded payload bytes (fragments * FRAGMENT_SIZE)
        uint32_t orig_len;    // original (raw) payload length in bytes
        uint64_t pts;         // presentation timestamp in milliseconds
    };
#pragma pack(pop)

    constexpr size_t FEC_PACKET_HEADER_SIZE = sizeof(FecPacketHeader);

#pragma pack(push,1)
    struct FecPacket {
        uint32_t client_id;
        uint32_t packet_seq;
        uint16_t fec_k;
        uint16_t fec_m;
        uint16_t flags;
        uint16_t fragments;
        uint32_t orig_len;
        uint64_t pts;
        std::vector<char> payload; // decoded payload (after decode())
    };
#pragma pack(pop)

/**
 * @brief StubFec provides a future-compatible API for Reed-Solomon coder (rscoder).
 *
 * This stub currently performs RS encoding (using rscoder) and a 'fast-path'
 * decode which, when all fragments are present, simply extracts the DATA_BLOCK
 * bytes from each fragment (systematic code). If fragments are missing,
 * full RS decode could be used as a fallback.
 *
 * The API includes:
 *  - encode_with_header(...) -> returns [header | encoded_payload]
 *  - parse_header(...) -> read header from bytes
 *  - decode_payload(...) and decode_packet(...)
 */
    class StubFec {
    public:
        StubFec() = default;
        ~StubFec() = default;

        std::vector<char> encode_with_header(uint32_t client_id,
                                             uint32_t packet_seq,
                                             uint16_t fec_k,
                                             uint16_t fec_m,
                                             uint16_t flags,
                                             uint64_t pts,
                                             const char *data,
                                             size_t len);

        static FecPacketHeader parse_header(const char *hdr_bytes, size_t hdr_len);

        std::vector<char> decode_payload(const char *data, size_t len, uint16_t fragments, uint32_t orig_len);

        FecPacket decode_packet(const char *packet_bytes, size_t packet_len);
    };

} // namespace project::fec

#endif // PROJECT_ENCODER_HPP
