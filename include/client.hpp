/*
* @license
* (C) zachbabanov
*
*/

#ifndef PROJECT_CLIENT_HPP
#define PROJECT_CLIENT_HPP

#pragma once

#include <common.hpp>

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>

namespace project {
    namespace client {

        class Client {
        public:
            Client(const std::string &host, int port, const std::string &h264File, bool loop);
            ~Client();

            bool run();

            /// Set initial bitrate (kbps). 0 = unlimited.
            void set_initial_bitrate(uint32_t kbps);

        private:
            bool initAndConnect(project::common::sock_t &outTcp, project::common::sock_t &outUdp);
            bool sendTcpRegister(project::common::sock_t tcpSock, uint32_t seq);
            bool receiveTcpRegisterResp(project::common::sock_t tcpSock, uint32_t &assigned, int timeoutMs = 2000);
            bool udpStreamRun(project::common::sock_t sock);

            void closeSocketLocal(project::common::sock_t s);

            // Helpers
            static std::vector<std::vector<char>> extractAnnexBNals(const std::vector<char> &data);

            // TCP command listener (changes bitrate at runtime)
            void startTcpListener(project::common::sock_t tcpSock);
            void stopTcpListener();
            void tcpListenerLoop(project::common::sock_t tcpSock);

            // pacing
            void pace_before_send(size_t bytes);

        private:
            std::string host_;
            int tcpPort_;
            int udpPort_;
            std::string h264File_;
            bool loop_;
            uint32_t clientId_;
            uint32_t packetSeq_;

            // rate control
            std::atomic<uint32_t> bitrate_kbps_; // 0 = unlimited
            std::mutex rate_mtx_;
            double tokens_; // bytes currently available
            std::chrono::steady_clock::time_point last_fill_;

            // TCP listener thread
            std::thread tcp_listener_thread_;
            std::atomic<bool> stop_tcp_listener_;
        };

    } // namespace client
} // namespace project

#endif // PROJECT_CLIENT_HPP
