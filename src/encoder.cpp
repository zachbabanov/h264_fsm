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
    memcpy(packet.data() + FEC_PACKET_HEADER_SIZE, payload, payload_len);

    LOG_FEC_INFO("encode_with_header: client_id={} seq={} fec_k={} fec_m={} pts={} orig_len={} fragments={} encoded_len={} total_packet={}",
                 client_id, packet_seq, fec_k, fec_m, pts, payload_len, fec_k, fec_k * 255, packet.size());

    return packet;
}

FecDecodedPacket StubFec::decode_packet(const char* data, size_t len) {
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

    return pkt;
}
