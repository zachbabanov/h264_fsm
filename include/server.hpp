#ifndef PROJECT_SERVER_HPP
#define PROJECT_SERVER_HPP

#pragma once

#include "common.hpp"
#include "player.hpp"
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <queue>

namespace project {
    namespace server {

        using project::common::sock_t;

// Connection state machine
        enum class State : int {
            READING,
            PROCESSING,
            WRITING,
            CLOSING
        };

        struct VideoFrame {
            std::vector<char> data;
            uint64_t pts; // Presentation timestamp in milliseconds
            bool is_keyframe;
        };

        struct Connection {
            sock_t fd;
            uint32_t clientId;
            State state;
            std::string inBuffer;     // raw bytes received from socket
            std::string playerBuffer; // bytes pending to write to player

            // Buffering with timestamps
            std::queue<VideoFrame> frame_queue;
            uint64_t last_pts;
            uint64_t first_pts;
            bool first_frame_received;

            std::vector<char> sps_data;
            std::vector<char> pps_data;
            bool sps_received{false};
            bool pps_received{false};

            std::unique_ptr<project::player::PlayerProcess> player;

            Connection() : fd(INVALID_SOCK), clientId(0), state(State::READING),
                           last_pts(0), first_pts(0), first_frame_received(false) {}
            explicit Connection(sock_t s) : fd(s), clientId(0), state(State::READING),
                                            last_pts(0), first_pts(0), first_frame_received(false) {}
        };

        class Server {
        public:
            Server(int tcpPort, const std::string &playerCmd);
            ~Server();

            bool start();
            void runLoop();

        private:
            bool setupListenSocket();
            void acceptNewConnections();
            void handleClientEvent(sock_t fd, uint32_t events = 0);
            void handlePlayerFdEvent(int playerFd);
            void handleUdpPacket(sock_t udpFd);
            void closeConnection(sock_t fd);
            void flushPlayerBuffer(Connection &c);
            void processFrameQueue(Connection &c);

            // helper to analyze nal types in a payload
            static void analyze_nal_types(const std::vector<char> &payload, bool &hasSps, bool &hasPps, bool &hasIdr);

        private:
            int tcpPort_;
            int udpPort_;
            sock_t listenSocket_;
#ifdef __linux__
            int epollFd_;
            std::unordered_map<int, sock_t> playerFdToClientFd_;
#endif
            std::unordered_map<sock_t, Connection> clients_;
            uint32_t nextClientId_;
            std::string playerCmd_;
        };

    } // namespace server
} // namespace project

#endif // PROJECT_SERVER_HPP