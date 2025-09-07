#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "common.hpp"
#include "encoder.hpp"

using namespace project::common;
using namespace project::fec;

TEST_CASE("hton/ntoh roundtrip uint32", "[common]") {
    uint32_t v = 0x12345678;
    uint32_t net = hton_u32(v);
    uint32_t host = ntoh_u32(net);
    REQUIRE(host == v);
}

TEST_CASE("hton/ntoh roundtrip uint16", "[common]") {
    uint16_t v = 0xABCD;
    uint16_t net = hton_u16(v);
    uint16_t host = ntoh_u16(net);
    REQUIRE(host == v);
}

TEST_CASE("UdpHeader serialize/deserialize", "[common]") {
    UdpHeader h{};
    h.client_id = hton_u32(42);
    h.command_id = hton_u16(CMD_REGISTER);
    h.flags = hton_u16(0x5);
    h.seq = hton_u32(1234);

    // raw bytes roundtrip
    UdpHeader r;
    memcpy(&r, &h, sizeof(h));
    REQUIRE(ntoh_u32(r.client_id) == 42);
    REQUIRE(ntoh_u16(r.command_id) == CMD_REGISTER);
    REQUIRE(ntoh_u16(r.flags) == 0x5);
    REQUIRE(ntoh_u32(r.seq) == 1234);
}
