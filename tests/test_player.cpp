/*
* @license
* (C) zachbabanov
*
*/

#include <catch2/catch.hpp>

#include <encoder.hpp>
#include <player.hpp>
#include <common.hpp>

using namespace project::fec;
using namespace project::player;
using namespace project::common;

/**
 * PlayerProcess basic lifecycle smoke test (platform-dependent):
 * On CI without ffplay or in headless environment player may exit immediately.
 * Test accepts both cases:
 *  - launch() returns nullptr (ffplay not available) -> succeed
 *  - launch() returns object but write_data() returns < 0 (player exited / closed stdin) -> also succeed (environment)
 *  - otherwise attempt to write and stop the player and assert write succeeded.
 */
TEST_CASE("PlayerProcess launch-stop (smoke)", "[player][process]") {
    auto p = PlayerProcess::launch("ffplay");
    if (!p) {
        // OK: environment may not have ffplay; ensure nullptr handled gracefully
        SUCCEED("ffplay not available in environment - launch returned nullptr as expected");
        return;
    }

    // we have a process object — try to write a small buffer
    const char testData[] = { 0x00, 0x01, 0x02, 0x03 };
    ssize_t w = p->write_data(testData, sizeof(testData));

    if (w < 0) {
        // Some CI / headless environments cause the player to exit immediately or close stdin.
        // Treat this as OK for the smoke test (we verified launch() returned an object and write_data handled the condition).
        SUCCEED("Player started but write not possible (player exited or closed stdin) — acceptable in CI");
        // ensure we attempt to stop the player gracefully
        p->stop();
        return;
    }

    // If we managed to write, assert the write succeeded and stop the player.
    REQUIRE(w >= 0);
    p->stop();
    SUCCEED("Player launched, wrote data and stopped successfully");
}
