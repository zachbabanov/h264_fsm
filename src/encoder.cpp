#include "encoder.hpp"
#include "logger.hpp"
#include "common.hpp"
#include <vector>
#include <cstring>
#include <cassert>
#include <sstream>
#include <iomanip>

#include "rs.hpp" // rscoder header (must be available via CMake FetchContent)

using namespace project::fec;
using namespace project::log;
using namespace project::common;

/*
 * Implementation details:
 * DATA_BLOCK = 128, PARITY_BLOCK = 128 => FRAGMENT_SIZE = 256
 */
static constexpr size_t DATA_BLOCK = 128;
static constexpr size_t PARITY_BLOCK = 127;
static constexpr size_t FRAGMENT_SIZE = DATA_BLOCK + PARITY_BLOCK; // 256

// Helper conversions
static uint16_t h16(uint16_t v) { return hton_u16(v); }
static uint32_t h32(uint32_t v) { return hton_u32(v); }
static uint64_t h64(uint64_t v) { return hton_u64(v); }
static uint16_t n16(uint16_t v) { return ntoh_u16(v); }
static uint32_t n32(uint32_t v) { return ntoh_u32(v); }
static uint64_t n64(uint64_t v) { return ntoh_u64(v); }

/**
 * Hex-dump helper (first N bytes)
 */
static std::string hexdump_prefix(const char *data, size_t len, size_t max_bytes = 64) {
    size_t n = std::min(len, max_bytes);
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        unsigned int b = (unsigned char)data[i];
        ss << std::setw(2) << b;
        if (i + 1 < n) ss << " ";
    }
    if (len > n) ss << " ... (+" << (len - n) << " bytes)";
    ss << std::dec;
    return ss.str();
}

/**
 * Build a wire-ready packet: header (network order) + payload (encoded bytes).
 */
std::vector<char> StubFec::encode_with_header(uint32_t client_id,
                                              uint32_t packet_seq,
                                              uint16_t fec_k,
                                              uint16_t fec_m,
                                              uint16_t flags,
                                              uint64_t pts,
                                              const char *data,
                                              size_t len) {
    RS::ReedSolomon<DATA_BLOCK, PARITY_BLOCK> coder;

    size_t full_blocks = (len + DATA_BLOCK - 1) / DATA_BLOCK;
    if (full_blocks == 0) full_blocks = 1;
    uint16_t fragments = (uint16_t)full_blocks;

    size_t encoded_payload_len = fragments * FRAGMENT_SIZE;

    FecPacketHeader hdr{};
    hdr.client_id = h32(client_id);
    hdr.packet_seq = h32(packet_seq);
    hdr.fec_k = h16(fec_k);
    hdr.fec_m = h16(fec_m);
    hdr.flags = h16(flags);
    hdr.fragments = h16(fragments);
    hdr.payload_len = h32((uint32_t)encoded_payload_len);
    hdr.orig_len = h32((uint32_t)len);
    hdr.pts = h64(pts);

    std::vector<char> out;
    out.resize(FEC_PACKET_HEADER_SIZE + encoded_payload_len);

    std::memcpy(out.data(), &hdr, FEC_PACKET_HEADER_SIZE);

    size_t written = 0;
    for (uint16_t i = 0; i < fragments; ++i) {
        char in_block[DATA_BLOCK];
        std::memset(in_block, 0, DATA_BLOCK);
        size_t offset = (size_t)i * DATA_BLOCK;
        size_t take = std::min((size_t)DATA_BLOCK, (size_t)((offset < len) ? (len - offset) : 0));
        if (take) std::memcpy(in_block, data + offset, take);

        char encoded_block[FRAGMENT_SIZE];
        coder.Encode(in_block, encoded_block);

        std::memcpy(out.data() + FEC_PACKET_HEADER_SIZE + written, encoded_block, FRAGMENT_SIZE);
        written += FRAGMENT_SIZE;
    }
    assert(written == encoded_payload_len);

    LOG_FEC_INFO("encode_with_header: client_id={} seq={} fec_k={} fec_m={} pts={} orig_len={} fragments={} encoded_len={} total_packet={}",
                 client_id, packet_seq, fec_k, fec_m, pts, (uint32_t)len, (unsigned)fragments, (uint32_t)encoded_payload_len, (uint32_t)out.size());

    // Optional debug: hexdump of first fragment header bytes
    if (encoded_payload_len > 0) {
        std::string hd = hexdump_prefix(out.data() + FEC_PACKET_HEADER_SIZE, std::min((size_t)64, encoded_payload_len), 32);
        LOG_FEC_DEBUG("encode_with_header: first_encoded_fragment_hex={}", hd.c_str());
    }

    return out;
}

/**
 * Parse wire header into host-order header.
 */
FecPacketHeader StubFec::parse_header(const char *hdr_bytes, size_t hdr_len) {
    FecPacketHeader net{};
    FecPacketHeader host{};
    if (hdr_len < FEC_PACKET_HEADER_SIZE) return host;
    std::memcpy(&net, hdr_bytes, FEC_PACKET_HEADER_SIZE);
    host.client_id = n32(net.client_id);
    host.packet_seq = n32(net.packet_seq);
    host.fec_k = n16(net.fec_k);
    host.fec_m = n16(net.fec_m);
    host.flags = n16(net.flags);
    host.fragments = n16(net.fragments);
    host.payload_len = n32(net.payload_len);
    host.orig_len = n32(net.orig_len);
    host.pts = n64(net.pts);
    return host;
}

/**
 * Decode payload bytes (converts encoded fragments back to original payload).
 */
std::vector<char> StubFec::decode_payload(const char *data, size_t len, uint16_t fragments, uint32_t orig_len) {
    std::vector<char> out;
    if (fragments == 0) return out;

    RS::ReedSolomon<DATA_BLOCK, PARITY_BLOCK> coder;
    out.reserve((size_t)orig_len);

    size_t expected_len = (size_t)fragments * FRAGMENT_SIZE;
    if (len < expected_len) {
        LOG_FEC_ERROR("decode_payload: insufficient encoded bytes: expected={} have={}", (uint32_t)expected_len, (uint32_t)len);
        return out;
    }

    for (uint16_t i = 0; i < fragments; ++i) {
        const char *frag_ptr = data + (size_t)i * FRAGMENT_SIZE;
        char decoded[DATA_BLOCK];
        std::memset(decoded, 0, DATA_BLOCK);
        bool ok = coder.Decode(frag_ptr, decoded);
        if (!ok) {
            // Hexdump first bytes of failing fragment + prefix of whole payload for diagnostics
            std::string frag_hex = hexdump_prefix(frag_ptr, FRAGMENT_SIZE, 64);
            std::string payload_hex = hexdump_prefix(data, std::min((size_t)len, (size_t)256), 128);
            LOG_FEC_ERROR("decode_payload: RS decode failed for fragment {}/{}. frag_hex={} payload_prefix={}",
                          (unsigned)i, (unsigned)fragments, frag_hex.c_str(), payload_hex.c_str());
            return {};
        }
        size_t to_take = DATA_BLOCK;
        if ((size_t)i == (size_t)fragments - 1) {
            size_t produced = out.size();
            size_t remain = (orig_len > produced) ? (size_t)(orig_len - produced) : 0;
            to_take = std::min(remain, (size_t)DATA_BLOCK);
        }
        if (to_take) out.insert(out.end(), decoded, decoded + to_take);
    }

    if (out.size() > orig_len) out.resize(orig_len);

    LOG_FEC_DEBUG("decode_payload: decoded_len={} orig_len={} fragments={}", (uint32_t)out.size(), orig_len, (unsigned)fragments);
    return out;
}

/**
 * Decode full packet (header + payload) and return structured data.
 */
FecPacket StubFec::decode_packet(const char *packet_bytes, size_t packet_len) {
    FecPacket pkt{};
    if (packet_len < (int)FEC_PACKET_HEADER_SIZE) return pkt;
    FecPacketHeader hdr = parse_header(packet_bytes, FEC_PACKET_HEADER_SIZE);
    pkt.client_id = hdr.client_id;
    pkt.packet_seq = hdr.packet_seq;
    pkt.fec_k = hdr.fec_k;
    pkt.fec_m = hdr.fec_m;
    pkt.flags = hdr.flags;
    pkt.fragments = hdr.fragments;
    pkt.pts = hdr.pts;
    size_t payload_len = hdr.payload_len;
    size_t total_needed = FEC_PACKET_HEADER_SIZE + payload_len;
    if ((size_t)packet_len < total_needed) {
        LOG_FEC_DEBUG("decode_packet: incomplete expected={} have={}", (uint32_t)total_needed, (uint32_t)packet_len);
        return pkt;
    }
    const char *payload_ptr = packet_bytes + FEC_PACKET_HEADER_SIZE;
    pkt.payload = decode_payload(payload_ptr, payload_len, (uint16_t)hdr.fragments, hdr.orig_len);

    LOG_FEC_INFO("decode_packet: client_id={} seq={} fec_k={} fec_m={} pts={} payload_len={} decoded_len={} fragments={}",
                 pkt.client_id, pkt.packet_seq, pkt.fec_k, pkt.fec_m, pkt.pts, (uint32_t)payload_len, (uint32_t)pkt.payload.size(), (unsigned)hdr.fragments);

    return pkt;
}
