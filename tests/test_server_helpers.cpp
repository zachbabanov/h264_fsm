#include <catch2/catch.hpp>
#include "server.hpp"
#include "common.hpp"

using namespace project::server;
using namespace project::common;

TEST_CASE("enforce_player_buf_limits soft drop", "[server_helpers]") {
    Connection c;
    // make buffer > soft limit but < hard
    c.playerBuffer.assign(MAX_PLAYER_BUFFER + 1024, 'x');
    helpers::enforcePlayerBufferLimits(c, "test_soft");
    REQUIRE(c.state != State::CLOSING);
    REQUIRE(c.playerBuffer.size() <= (MAX_PLAYER_BUFFER + 1024));
    // after drop, buffer should be smaller than original
    REQUIRE(c.playerBuffer.size() <= (MAX_PLAYER_BUFFER + 1024) - ((MAX_PLAYER_BUFFER + 1024)/2));
}

TEST_CASE("enforce_player_buf_limits hard close", "[server_helpers]") {
    Connection c;
    c.playerBuffer.assign(MAX_PLAYER_BUFFER_HARD + 1, 'y');
    c.state = State::READING;
    helpers::enforcePlayerBufferLimits(c, "test_hard");
    REQUIRE(c.state == State::CLOSING);
}
