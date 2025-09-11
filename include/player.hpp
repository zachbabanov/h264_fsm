/*
* @license
* (C) zachbabanov
*
*/

#ifndef PROJECT_PLAYER_HPP
#define PROJECT_PLAYER_HPP

#pragma once

#include <common.hpp>

#include <string>
#include <vector>
#include <memory>

namespace project::player {

/**
 * @brief PlayerProcess abstracts launching an external player (ffplay) and writing bytes to its stdin.
 *
 * - On Linux it uses pipe + execvp; write_data directly writes to pipe (non-blocking).
 * - On Windows it creates process with pipe and a dedicated writer thread that drains an internal queue.
 *
 * The class is intentionally minimal and focused on streaming raw H.264 bytes to ffplay's stdin.
 */
class PlayerProcess {
public:
    static std::unique_ptr<PlayerProcess> launch(const std::string &player_cmd, const std::vector<std::string> &app_args = {});

    ~PlayerProcess();

    /**
     * @brief Write buffer to player stdin.
     * @return number of bytes written or queued, or -1 on error.
     */
    ssize_t write_data(const char *buf, size_t len);

    /**
     * @brief Returns an FD suitable for epoll notifications on Linux, or -1 if not supported.
     */
    int get_write_fd() const;

    /// Stop the player process and clean up resources.
    void stop();

private:
    PlayerProcess();
    struct Impl;
    Impl *impl_;
};

} // namespace project::player

#endif // PROJECT_PLAYER_HPP
