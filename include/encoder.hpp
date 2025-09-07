#ifndef PROJECT_ENCODER_HPP
#define PROJECT_ENCODER_HPP

#pragma once

#include <vector>
#include <cstddef>
#include <cstdint>

namespace project::fec {

/**
 * @brief Header prepended to each encoded FEC packet.
 *
 * Fields are stored on the wire in network byte order.
 *
 * New fields:
 *   - fragments: number of encoded fragments (blocks) inside payload
 *   - orig_len: original raw payload length (bytes) before FEC/padding
 *
 * This allows payload to contain multiple RS-encoded fragments.
 */
#pragma pack(push,1)
    struct FecPacketHeader {
        uint32_t client_id;   // client identifier
        uint32_t packet_seq;  // packet sequence number
        uint16_t fec_k;       // data symbols (for RS) - host order in parsed struct
        uint16_t fec_m;       // parity symbols (for RS)
        uint16_t flags;       // reserved flags
        uint16_t fragments;   // number of encoded fragments inside payload
        uint32_t payload_len; // length of encoded payload in bytes (not counting header)
        uint32_t orig_len;    // original payload length in bytes before FEC/padding
        uint64_t pts;         // presentation timestamp in milliseconds
    };
#pragma pack(pop)

    constexpr size_t FEC_PACKET_HEADER_SIZE = sizeof(FecPacketHeader);

    struct FecPacket {
        uint32_t client_id;
        uint32_t packet_seq;
        uint16_t fec_k;
        uint16_t fec_m;
        uint16_t flags;
        uint16_t fragments;
        uint64_t pts;
        std::vector<char> payload; // decoded payload (after decode())
    };

/**
 * @brief StubFec provides a future-compatible API for Reed-Solomon coder (rscoder).
 *
 * This implementation uses rscoder (rs.hpp) underneath. It encodes arbitrary input
 * data by splitting it into fixed-size data blocks (DATA_BLOCK = 128) and producing
 * parity blocks (PARITY_BLOCK = 128) so each encoded fragment is 256 bytes.
 *
 * Public API (unchanged signatures):
 *  - encode_with_header(...) -> returns [header | encoded_payload]
 *  - parse_header(...) -> read header from bytes (and convert to host order)
 *  - decode_payload(...) and decode_packet(...)
 *
 * NOTE: encode_with_header now fills header.fragments and header.orig_len.
 */
    class StubFec {
    public:
        StubFec() = default;
        ~StubFec() = default;

        /**
         * @brief Encode data and return bytes ready to send on the wire:
         *        [FecPacketHeader | encoded_payload]
         *
         * Encodes input `data` by splitting into DATA_BLOCK sized pieces and encoding
         * each with RS<128,128> into 256-byte fragments. The header.fragments field
         * contains the number of fragments placed into the payload.
         *
         * @param client_id client identifier to embed
         * @param packet_seq monotonic packet seq for this client
         * @param fec_k number of data symbols (for future RS) (not used by rscoder template)
         * @param fec_m number of parity symbols (for future RS)
         * @param flags reserved flags
         * @param pts presentation timestamp in milliseconds
         * @param data input bytes
         * @param len input length
         * @return vector<char> full packet bytes (header + encoded payload)
         */
        std::vector<char> encode_with_header(uint32_t client_id,
                                             uint32_t packet_seq,
                                             uint16_t fec_k,
                                             uint16_t fec_m,
                                             uint16_t flags,
                                             uint64_t pts,
                                             const char *data,
                                             size_t len);

        /**
         * @brief Parse header (network->host) from contiguous header bytes.
         *
         * Caller must ensure hdr_len >= FEC_PACKET_HEADER_SIZE.
         */
        static FecPacketHeader parse_header(const char *hdr_bytes, size_t hdr_len);

        /**
         * @brief Decode a payload (convert encoded fragments back into original payload).
         *
         * Returns decoded raw bytes (original payload length equals header.orig_len).
         */
        std::vector<char> decode_payload(const char *data, size_t len, uint16_t fragments, uint32_t orig_len);

        /**
         * @brief Decode a full packet (header + payload) and return FecPacket.
         *
         * If packet incomplete or decoding fails, returned payload will be empty.
         */
        FecPacket decode_packet(const char *packet_bytes, size_t packet_len);
    };

} // namespace project::fec

#endif // PROJECT_ENCODER_HPP
