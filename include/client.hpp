#ifndef PROJECT_CLIENT_HPP
#define PROJECT_CLIENT_HPP

#pragma once

#include "common.hpp"
#include <string>
#include <vector>

namespace project {
    namespace client {

        class Client {
        public:
            Client(const std::string &host, int port, const std::string &h264File, bool loop);
            ~Client();

            bool run();

        private:
            bool initAndConnect(project::common::sock_t &outTcp, project::common::sock_t &outUdp);
            bool sendUdpRegister(project::common::sock_t udpSock, uint32_t seq);
            bool receiveUdpRegisterResp(project::common::sock_t udpSock, uint32_t &assigned, int timeoutMs = 2000);
            bool tcpStreamRun(project::common::sock_t sock);

            void closeSocketLocal(project::common::sock_t s);

            // Helpers
            static std::vector<std::vector<char>> extractAnnexBNals(const std::vector<char> &data);

        private:
            std::string host_;
            int tcpPort_;
            int udpPort_;
            std::string h264File_;
            bool loop_;
            uint32_t clientId_;
            uint32_t packetSeq_;
        };

    } // namespace client
} // namespace project

#endif // PROJECT_CLIENT_HPP
