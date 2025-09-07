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
 */
#pragma pack(push,1)
struct FecPacketHeader {
    uint32_t client_id;   // client identifier
    uint32_t packet_seq;  // packet sequence number
    uint16_t fec_k;       // data symbols (for RS)
    uint16_t fec_m;       // parity symbols (for RS)
    uint16_t flags;       // reserved flags
    uint32_t payload_len; // length of encoded payload in bytes (not counting header)
};
#pragma pack(pop)

constexpr size_t FEC_PACKET_HEADER_SIZE = sizeof(FecPacketHeader);

struct FecPacket {
    uint32_t client_id;
    uint32_t packet_seq;
    uint16_t fec_k;
    uint16_t fec_m;
    uint16_t flags;
    std::vector<char> payload; // decoded payload (after decode())
};

/**
 * @brief StubFec provides a future-compatible API for Reed-Solomon coder (rscoder).
 *
 * This stub currently performs pass-through encoding/decoding (identity).
 * The API includes:
 *  - encode_with_header(...) -> returns [header | encoded_payload]
 *  - parse_header(...) -> read header from bytes
 *  - decode_payload(...) and decode_packet(...)
 *
 * The header carries fec_k/fec_m and packet_seq to be compatible with rscoder usage later.
 */
class StubFec {
public:
    StubFec() = default;
    ~StubFec() = default;

    /**
     * @brief Encode data and return bytes ready to send on the wire:
     *        [FecPacketHeader | encoded_payload]
     *
     * @param client_id client identifier to embed
     * @param packet_seq monotonic packet seq for this client
     * @param fec_k number of data symbols (for future RS)
     * @param fec_m number of parity symbols (for future RS)
     * @param flags reserved flags
     * @param data input bytes
     * @param len input length
     * @return vector<char> full packet bytes (header + encoded payload)
     */
    std::vector<char> encode_with_header(uint32_t client_id,
                                         uint32_t packet_seq,
                                         uint16_t fec_k,
                                         uint16_t fec_m,
                                         uint16_t flags,
                                         const char *data,
                                         size_t len);

    /**
     * @brief Parse header (network->host) from contiguous header bytes.
     *
     * Caller must ensure hdr_len >= FEC_PACKET_HEADER_SIZE.
     */
    static FecPacketHeader parse_header(const char *hdr_bytes, size_t hdr_len);

    /**
     * @brief Decode a payload (stub: identity).
     */
    std::vector<char> decode_payload(const char *data, size_t len);

    /**
     * @brief Decode a full packet (header + payload) and return FecPacket.
     *
     * If packet incomplete or decoding fails, returned payload will be empty.
     */
    FecPacket decode_packet(const char *packet_bytes, size_t packet_len);
};

} // namespace project::fec

#endif // PROJECT_ENCODER_HPP
