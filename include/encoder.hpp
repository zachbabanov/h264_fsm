/*
* @license
* (C) zachbabanov
*
*/

#ifndef PROJECT_ENCODER_HPP
#define PROJECT_ENCODER_HPP

#pragma once

#include <cstdint>
#include <cstddef>
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
        uint32_t client_id;
        uint32_t packet_seq;
        uint16_t fec_k;
        uint16_t fec_m;
        uint16_t flags;
        uint64_t pts;
        uint32_t payload_len;
    };
#pragma pack(pop)

    constexpr size_t FEC_PACKET_HEADER_SIZE = sizeof(FecPacketHeader);

#pragma pack(push,1)
    struct FecDecodedPacket {
        uint32_t client_id;
        uint32_t packet_seq;
        uint16_t fec_k;
        uint16_t fec_m;
        uint16_t flags;
        uint64_t pts;
        std::vector<char> payload;
    };
#pragma pack(pop)

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

        static std::vector<char> encode_with_header(uint32_t client_id,
                                                    uint32_t packet_seq,
                                                    uint16_t fec_k,
                                                    uint16_t fec_m,
                                                    uint16_t flags,
                                                    uint64_t pts,
                                                    const char* payload,
                                                    size_t payload_len);

        static FecPacketHeader parse_header(const char* data, size_t len);

        static FecDecodedPacket decode_packet(const char* data, size_t len);
    };

} // namespace project::fec

#endif // PROJECT_ENCODER_HPP
