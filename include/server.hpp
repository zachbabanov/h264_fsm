/*
* @license
* (C) zachbabanov
*
*/

#ifndef PROJECT_SERVER_HPP
#define PROJECT_SERVER_HPP

#pragma once

#include <common.hpp>
#include <player.hpp>

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <queue>
#include <cstdint>

#include <netinet/in.h>

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
            sock_t tcp_fd;      // TCP socket for commands
            sock_t udp_fd;      // UDP socket for video (not used directly, stored for client address)
            uint32_t clientId;
            State state;
            std::string inBuffer;     // raw bytes received from TCP socket
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

            // playback timing (per-connection)
            std::chrono::steady_clock::time_point playback_start; // wallclock when first frame is scheduled
            bool playback_started;

            // UDP client address for video
            sockaddr_in udp_addr;
            bool udp_addr_set;

            Connection() : tcp_fd(INVALID_SOCK), udp_fd(INVALID_SOCK), clientId(0), state(State::READING),
                           last_pts(0), first_pts(0), first_frame_received(false),
                           sps_received(false), pps_received(false),
                           player(nullptr), playback_start(std::chrono::steady_clock::time_point{}), playback_started(false),
                           udp_addr_set(false) {}
            explicit Connection(sock_t s) : tcp_fd(s), udp_fd(INVALID_SOCK), clientId(0), state(State::READING),
                                            last_pts(0), first_pts(0), first_frame_received(false),
                                            sps_received(false), pps_received(false),
                                            player(nullptr), playback_start(std::chrono::steady_clock::time_point{}), playback_started(false),
                                            udp_addr_set(false) {}
        };

        //
        // InProgress: structure used to reassemble UDP fragments into one encoded packet
        // Extended to keep FEC meta duplicated in UDP fragment header and per-fragment offsets
        //
        struct InProgress {
            uint32_t client_id;
            uint32_t packet_seq;
            uint32_t total_packet_len;
            uint16_t total_frags;
            uint64_t pts;

            // Duplicated FEC meta (taken from UdpVideoFragmentHeader)
            uint16_t fec_k;
            uint16_t fec_m;
            uint32_t encoded_payload_len; // length of encoded payload bytes (packet_len - FEC_PACKET_HEADER_SIZE)

            // Reassembly buffer and bookkeeping
            std::vector<char> buffer;                // size == total_packet_len
            std::vector<char> fragment_received;     // per-fragment marker (0/1)
            std::vector<uint32_t> frag_offsets;      // per-fragment offset into total packet
            std::vector<uint16_t> frag_lens;         // per-fragment payload length
            size_t received_bytes;
            std::chrono::steady_clock::time_point first_seen;

            InProgress()
                    : client_id(0), packet_seq(0), total_packet_len(0), total_frags(0),
                      pts(0), fec_k(0), fec_m(0), encoded_payload_len(0),
                      received_bytes(0), first_seen(std::chrono::steady_clock::now()) {}
        };

        inline uint64_t make_inprogress_key(uint32_t client_id, uint32_t packet_seq) {
            return ( (uint64_t)client_id << 32 ) | (uint64_t)packet_seq;
        }

        class Server {
        public:
            Server(int tcpPort, const std::string &playerCmd);
            ~Server();

            bool start();
            void runLoop();

        private:
            bool setupListenSocket();
            void acceptNewConnections();
            void handleTcpEvent(sock_t fd, uint32_t events = 0);
            void handleUdpVideoEvent(sock_t udpFd);
            void handlePlayerFdEvent(int playerFd);
            void closeConnection(sock_t fd);
            void flushPlayerBuffer(Connection &c);
            void processFrameQueue(Connection &c);

            // helper to analyze nal types in a payload
            static void analyze_nal_types(const std::vector<char> &payload, bool &hasSps, bool &hasPps, bool &hasIdr);

        private:
            int tcpPort_;
            int udpPort_;
            sock_t tcpListenSocket_;
            sock_t udpVideoSocket_; // UDP socket for video
#ifdef __linux__
            int epollFd_;
            std::unordered_map<int, sock_t> playerFdToClientFd_;
#endif
            std::unordered_map<sock_t, Connection> clients_; // key is TCP socket fd

            // Map for reassembly of UDP fragments: key = (client_id<<32)|packet_seq
            std::unordered_map<uint64_t, InProgress> inprogress_map_;

            uint32_t nextClientId_;
            std::string playerCmd_;
        };

    } // namespace server
} // namespace project

#endif // PROJECT_SERVER_HPP
