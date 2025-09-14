/*
* @license
* (C) zachbabanov
*
*/

#include <encoder.hpp>
#include <common.hpp>
#include <logger.hpp>

#include <cstring>
#include <vector>
#include <chrono>

#ifdef __linux__
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

using namespace project::fec;
using namespace project::common;
using namespace project::log;

// Implementation of StubFec methods

FecPacketHeader StubFec::parse_header(const char* data, size_t len) {
    FecPacketHeader hdr{};
    if (len < FEC_PACKET_HEADER_SIZE) {
        return hdr;
    }
    memcpy(&hdr, data, FEC_PACKET_HEADER_SIZE);
    hdr.client_id = ntoh_u32(hdr.client_id);
    hdr.packet_seq = ntoh_u32(hdr.packet_seq);
    hdr.fec_k = ntoh_u16(hdr.fec_k);
    hdr.fec_m = ntoh_u16(hdr.fec_m);
    hdr.flags = ntoh_u16(hdr.flags);
    hdr.pts = ntoh_u64(hdr.pts);
    hdr.payload_len = ntoh_u32(hdr.payload_len);
    return hdr;
}

std::vector<char> StubFec::encode_with_header(uint32_t client_id, uint32_t packet_seq, uint16_t fec_k, uint16_t fec_m, uint16_t flags, uint64_t pts, const char* payload, size_t payload_len) {
    using clk = std::chrono::high_resolution_clock;
    auto t0 = clk::now();

    FecPacketHeader hdr{};
    hdr.client_id = hton_u32(client_id);
    hdr.packet_seq = hton_u32(packet_seq);
    hdr.fec_k = hton_u16(fec_k);
    hdr.fec_m = hton_u16(fec_m);
    hdr.flags = hton_u16(flags);
    hdr.pts = hton_u64(pts);
    hdr.payload_len = hton_u32((uint32_t)payload_len);

    std::vector<char> packet;
    packet.resize(FEC_PACKET_HEADER_SIZE + payload_len);
    memcpy(packet.data(), &hdr, FEC_PACKET_HEADER_SIZE);
    if (payload_len) memcpy(packet.data() + FEC_PACKET_HEADER_SIZE, payload, payload_len);

    auto t1 = clk::now();
    double encode_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0).count();

    // Important metric: encode time, packet sizes, fec params
    LOG_FEC_INFO("encode: client_id={} seq={} fec_k={} fec_m={} pts={} orig_len={} encoded_len={} fragments_est={} encode_time_ms={:.3f}",
                 client_id, packet_seq, fec_k, fec_m, pts, (uint32_t)payload_len, (uint32_t)packet.size(), fec_k, encode_ms);

    return packet;
}

FecDecodedPacket StubFec::decode_packet(const char* data, size_t len) {
    using clk = std::chrono::high_resolution_clock;
    auto t0 = clk::now();

    FecDecodedPacket pkt{};
    if (len < FEC_PACKET_HEADER_SIZE) {
        return pkt;
    }

    FecPacketHeader hdr = parse_header(data, FEC_PACKET_HEADER_SIZE);
    if (len < FEC_PACKET_HEADER_SIZE + hdr.payload_len) {
        return pkt;
    }

    pkt.client_id = hdr.client_id;
    pkt.packet_seq = hdr.packet_seq;
    pkt.fec_k = hdr.fec_k;
    pkt.fec_m = hdr.fec_m;
    pkt.flags = hdr.flags;
    pkt.pts = hdr.pts;
    pkt.payload.assign(data + FEC_PACKET_HEADER_SIZE, data + FEC_PACKET_HEADER_SIZE + hdr.payload_len);

    auto t1 = clk::now();
    double decode_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0).count();

    // Important metric: decode time and payload size
    LOG_FEC_INFO("decode: client_id={} seq={} fec_k={} fec_m={} pts={} payload_len={} decode_time_ms={:.3f}",
                 pkt.client_id, pkt.packet_seq, pkt.fec_k, pkt.fec_m, pkt.pts, (uint32_t)pkt.payload.size(), decode_ms);

    return pkt;
}
