#include <catch2/catch.hpp>
#include "encoder.hpp"
#include <vector>
#include <string>

using namespace project::fec;

TEST_CASE("StubFec encode_with_header and decode_packet roundtrip small", "[encoder]") {
    StubFec fec;
    std::string s = "hello world";
    uint32_t cid = 42;
    uint32_t seq = 7;
    uint16_t k = 10, m = 2, flags = 0;
    auto packet = fec.encode_with_header(cid, seq, k, m, flags, s.data(), s.size());
    REQUIRE(packet.size() == FEC_PACKET_HEADER_SIZE + s.size());
    // parse header and decode
    auto pkt = fec.decode_packet(packet.data(), packet.size());
    REQUIRE(pkt.client_id == cid);
    REQUIRE(pkt.packet_seq == seq);
    REQUIRE(pkt.fec_k == k);
    REQUIRE(pkt.fec_m == m);
    REQUIRE(pkt.payload.size() == s.size());
    REQUIRE(std::string(pkt.payload.begin(), pkt.payload.end()) == s);
}

TEST_CASE("StubFec encode_with_header empty payload", "[encoder]") {
    StubFec fec;
    uint32_t cid = 1;
    uint32_t seq = 1;
    auto packet = fec.encode_with_header(cid, seq, 4, 2, 0, nullptr, 0);
    REQUIRE(packet.size() == FEC_PACKET_HEADER_SIZE);
    auto pkt = fec.decode_packet(packet.data(), packet.size());
    REQUIRE(pkt.payload.empty());
    REQUIRE(pkt.client_id == cid);
    REQUIRE(pkt.packet_seq == seq);
}

TEST_CASE("StubFec large payload", "[encoder]") {
    StubFec fec;
    std::vector<char> data(100000, 'A');
    uint32_t cid = 99;
    uint32_t seq = 123;
    auto packet = fec.encode_with_header(cid, seq, 20, 4, 0, data.data(), data.size());
    auto pkt = fec.decode_packet(packet.data(), packet.size());
    REQUIRE(pkt.payload.size() == data.size());
    REQUIRE(std::equal(pkt.payload.begin(), pkt.payload.end(), data.begin()));
}
