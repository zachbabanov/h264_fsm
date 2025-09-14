/*
* @license
* (C) zachbabanov
*
*/

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <encoder.hpp>
#include <common.hpp>

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

/*
 * FragMeta tests:
 * The code now inserts a small FragMeta (magic + replicated fields) at the start
 * of each fragment payload so server can recover header fields even when the
 * external UdpVideoFragmentHeader is corrupted in transit.
 *
 * Layout:
 *   uint32_t magic;
 *   uint32_t client_id;
 *   uint32_t packet_seq;
 *   uint32_t total_packet_len;
 *   uint32_t frag_offset;
 *   uint16_t frag_index;
 *   uint16_t total_frags;
 *
 * Total size = 24 bytes.
 */
TEST_CASE("FragMeta serialize/deserialize and sizes", "[fragmeta]") {
    // Define the constant used in client/server implementation
    const uint32_t FRAG_META_MAGIC = 0xFEC0FEC1u;

    // Local packed struct for test (network-order struct representation)
#pragma pack(push,1)
    struct FragMetaNet {
        uint32_t magic;
        uint32_t client_id;
        uint32_t packet_seq;
        uint32_t total_packet_len;
        uint32_t frag_offset;
        uint16_t frag_index;
        uint16_t total_frags;
    };
#pragma pack(pop)

    static_assert(sizeof(FragMetaNet) == 24, "FragMetaNet must be 24 bytes");

    FragMetaNet meta_net{};
    // Fill with network-order values as client does before sending
    meta_net.magic = hton_u32(FRAG_META_MAGIC);
    meta_net.client_id = hton_u32(0xDEADBEEF);
    meta_net.packet_seq = hton_u32(0x12345678);
    meta_net.total_packet_len = hton_u32(4096);
    meta_net.frag_offset = hton_u32(1024);
    meta_net.frag_index = hton_u16(2);
    meta_net.total_frags = hton_u16(5);

    // Copy to raw buffer (simulate received bytes)
    char buf[sizeof(FragMetaNet)];
    memcpy(buf, &meta_net, sizeof(meta_net));

    // Parse back (simulate server parsing FragMeta from payload)
    FragMetaNet parsed;
    memcpy(&parsed, buf, sizeof(parsed));

    REQUIRE(ntoh_u32(parsed.magic) == FRAG_META_MAGIC);
    REQUIRE(ntoh_u32(parsed.client_id) == 0xDEADBEEF);
    REQUIRE(ntoh_u32(parsed.packet_seq) == 0x12345678);
    REQUIRE(ntoh_u32(parsed.total_packet_len) == 4096);
    REQUIRE(ntoh_u32(parsed.frag_offset) == 1024);
    REQUIRE(ntoh_u16(parsed.frag_index) == 2);
    REQUIRE(ntoh_u16(parsed.total_frags) == 5);
}
