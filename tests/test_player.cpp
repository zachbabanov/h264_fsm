#include <catch2/catch.hpp>

#include "encoder.hpp"
#include "player.hpp"
#include "common.hpp"

using namespace project::fec;
using namespace project::player;
using namespace project::common;

/**
 * Sanity check: StubFec decode_payload returns exact input (pass-through).
 */
TEST_CASE("StubFec pass-through decode", "[fec][decode]") {
    StubFec encoder;
    const char data[] = "frame-bytes-123";
    auto enc = encoder.encode_with_header(1, 1, 5, 1, 0, data, sizeof(data)-1);

    // simulate receiving the whole encoded packet
    auto pkt = encoder.decode_packet(enc.data(), enc.size());
    REQUIRE(pkt.payload.size() == sizeof(data)-1);
    REQUIRE(std::string(pkt.payload.begin(), pkt.payload.end()) == std::string(data));
}

/**
 * PlayerProcess basic lifecycle smoke test (platform-dependent):
 * On CI without ffplay, launching may fail; test only validates API shape where possible.
 *
 * NOTE: This test avoids actually calling ffplay in CI. Instead, we test that launch()
 * may return nullptr when player not available, and that calling stop() is safe.
 */
TEST_CASE("PlayerProcess launch-stop (smoke)", "[player][process]") {
    // Try to launch a player. If not found, launch() returns nullptr.
    auto p = PlayerProcess::launch("ffplay");
    if (!p) {
        // OK: environment may not have ffplay; ensure nullptr handled gracefully
        SUCCEED("ffplay not available in environment - launch returned nullptr as expected");
    } else {
        // If started, attempt to write small buffer and then stop
        const char testData[] = { 0x00, 0x01, 0x02, 0x03 };
        ssize_t w = p->write_data(testData, sizeof(testData));
        // write_data either queues (windows) or writes (linux). Should not return error immediately.
        REQUIRE(w >= 0);
        p->stop();
        SUCCEED("Player launched, wrote data and stopped successfully");
    }
}
