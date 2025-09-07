#include "encoder.hpp"
#include "logger.hpp"
#include "common.hpp"
#include <vector>
#include <cstring>

using namespace project::fec;
using namespace project::log;
using namespace project::common;

/**
 * Build a wire-ready packet: header (network order) + payload (encoded bytes).
 * Currently payload is identical to input (pass-through).
 */
std::vector<char> StubFec::encode_with_header(uint32_t client_id,
                                              uint32_t packet_seq,
                                              uint16_t fec_k,
                                              uint16_t fec_m,
                                              uint16_t flags,
                                              const char *data,
                                              size_t len) {
    std::vector<char> out;
    FecPacketHeader hdr{};
    hdr.client_id = hton_u32(client_id);
    hdr.packet_seq = hton_u32(packet_seq);
    hdr.fec_k = hton_u16(fec_k);
    hdr.fec_m = hton_u16(fec_m);
    hdr.flags = hton_u16(flags);
    hdr.payload_len = hton_u32((uint32_t)len); // stub: encoded payload length == len

    out.resize(FEC_PACKET_HEADER_SIZE + len);
    std::memcpy(out.data(), &hdr, FEC_PACKET_HEADER_SIZE);
    if (len) std::memcpy(out.data() + FEC_PACKET_HEADER_SIZE, data, len);

    LOG_FEC_INFO("encode: client_id={} seq={} fec_k={} fec_m={} payload_len={} total_packet_len={}",
                 client_id, packet_seq, fec_k, fec_m, (uint32_t)len, (uint32_t)out.size());

    return out;
}

/**
 * Parse wire header into host-order header.
 */
FecPacketHeader StubFec::parse_header(const char *hdr_bytes, size_t hdr_len) {
    FecPacketHeader net{};
    if (hdr_len < FEC_PACKET_HEADER_SIZE) return net;
    std::memcpy(&net, hdr_bytes, FEC_PACKET_HEADER_SIZE);
    FecPacketHeader host{};
    host.client_id = ntoh_u32(net.client_id);
    host.packet_seq = ntoh_u32(net.packet_seq);
    host.fec_k = ntoh_u16(net.fec_k);
    host.fec_m = ntoh_u16(net.fec_m);
    host.flags = ntoh_u16(net.flags);
    host.payload_len = ntoh_u32(net.payload_len);
    return host;
}

/**
 * Decode payload bytes (pass-through).
 */
std::vector<char> StubFec::decode_payload(const char *data, size_t len) {
    std::vector<char> out;
    if (len == 0) return out;
    out.resize(len);
    std::memcpy(out.data(), data, len);
    LOG_FEC_DEBUG("decode_payload: decoded_len={}", (uint32_t)len);
    return out;
}

/**
 * Decode full packet (header + payload) and return structured data.
 */
FecPacket StubFec::decode_packet(const char *packet_bytes, size_t packet_len) {
    FecPacket pkt{};
    if (packet_len < FEC_PACKET_HEADER_SIZE) return pkt;
    FecPacketHeader hdr = parse_header(packet_bytes, FEC_PACKET_HEADER_SIZE);
    pkt.client_id = hdr.client_id;
    pkt.packet_seq = hdr.packet_seq;
    pkt.fec_k = hdr.fec_k;
    pkt.fec_m = hdr.fec_m;
    pkt.flags = hdr.flags;
    size_t payload_len = hdr.payload_len;
    if (packet_len < FEC_PACKET_HEADER_SIZE + payload_len) {
        LOG_FEC_DEBUG("decode_packet: incomplete expected={} have={}", (FEC_PACKET_HEADER_SIZE + payload_len), packet_len);
        return pkt;
    }
    const char *payload_ptr = packet_bytes + FEC_PACKET_HEADER_SIZE;
    pkt.payload = decode_payload(payload_ptr, payload_len);

    LOG_FEC_INFO("decode_packet: client_id={} seq={} fec_k={} fec_m={} payload_len={} decoded_len={} recovered={}",
                 pkt.client_id, pkt.packet_seq, pkt.fec_k, pkt.fec_m, (uint32_t)payload_len, (uint32_t)pkt.payload.size(), true);

    return pkt;
}
