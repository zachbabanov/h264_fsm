#include "client.hpp"
#include "common.hpp"
#include "encoder.hpp" // StubFec
#include "logger.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>

#ifdef __linux__
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
  #include <ws2tcpip.h>
#endif

using namespace project::client;
using namespace project::common;
using namespace project::fec;
using namespace project::log;

Client::Client(const std::string &host, int port, const std::string &h264File, bool loop)
        : host_(host), tcpPort_(port), udpPort_(port + 1), h264File_(h264File), loop_(loop), clientId_(0), packetSeq_(1) {}

Client::~Client() {}

bool Client::initAndConnect(sock_t &outTcpSock, sock_t &outUdpSock) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        LOG_GEN_ERROR("WSAStartup failed");
        return false;
    }
#endif

    addrinfo hints{};
    addrinfo *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host_.c_str(), std::to_string(tcpPort_).c_str(), &hints, &res) != 0) {
        LOG_GEN_ERROR("getaddrinfo failed for {}:{}", host_, tcpPort_);
        return false;
    }

    sock_t sock = INVALID_SOCK;
    for (addrinfo *rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCK) continue;

        setSocketNonBlocking(sock);
        enableSocketKeepAliveAndNoDelay(sock);

        int r = connect(sock, rp->ai_addr, (int)rp->ai_addrlen);
        if (r == 0) {
            break;
        } else {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) break;
#else
            if (errno == EINPROGRESS) break;
#endif
        }
        closeSocket(sock);
        sock = INVALID_SOCK;
    }
    freeaddrinfo(res);
    if (sock == INVALID_SOCK) {
        LOG_GEN_ERROR("Failed to create/connect TCP socket");
        return false;
    }
    outTcpSock = sock;
    LOG_NET_INFO("TCP socket initialized to {}:{}", host_, tcpPort_);

    sock_t udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udp == INVALID_SOCK) {
        LOG_GEN_ERROR("UDP socket creation failed");
        return false;
    }
    setSocketNonBlocking(udp);
    outUdpSock = udp;
    return true;
}

void Client::closeSocketLocal(sock_t s) {
    closeSocket(s);
}

bool Client::sendUdpRegister(sock_t udpSock, uint32_t seq) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, host_.c_str(), &dst.sin_addr);
    dst.sin_port = htons(udpPort_);

    UdpHeader hdr{};
    hdr.client_id = hton_u32(0);
    hdr.command_id = hton_u16(CMD_REGISTER);
    hdr.flags = 0;
    hdr.seq = hton_u32(seq);

    int rc = sendto(udpSock, (char*)&hdr, (int)sizeof(hdr), 0, (sockaddr*)&dst, sizeof(dst));
    if (rc < 0) {
        LOG_NET_INFO("sendto register failed");
        return false;
    }
    LOG_NET_INFO("UDP register sent seq={}", seq);
    return true;
}

bool Client::receiveUdpRegisterResp(sock_t udpSock, uint32_t &assigned, int timeoutMs) {
#ifdef __linux__
    pollfd pfd{};
    pfd.fd = udpSock;
    pfd.events = POLLIN;
    int r = poll(&pfd, 1, timeoutMs);
    if (r <= 0) return false;
    if (pfd.revents & POLLIN) {
        char buf[512];
        sockaddr_in src{};
        socklen_t sl = sizeof(src);
        int n = recvfrom(udpSock, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
        if (n >= (int)sizeof(UdpHeader)) {
            UdpHeader resp;
            memcpy(&resp, buf, sizeof(resp));
            if (ntoh_u16(resp.command_id) == CMD_REGISTER_RESP) {
                assigned = ntoh_u32(resp.client_id);
                return true;
            }
        }
    }
    return false;
#else
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udpSock, &rfds);
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    int r = select((int)(udpSock + 1), &rfds, nullptr, nullptr, &tv);
    if (r <= 0) return false;
    if (FD_ISSET(udpSock, &rfds)) {
        char buf[512];
        sockaddr_in src{};
        int sl = sizeof(src);
        int n = recvfrom(udpSock, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
        if (n >= (int)sizeof(UdpHeader)) {
            UdpHeader resp;
            memcpy(&resp, buf, sizeof(resp));
            if (ntoh_u16(resp.command_id) == CMD_REGISTER_RESP) {
                assigned = ntoh_u32(resp.client_id);
                return true;
            }
        }
    }
    return false;
#endif
}

/**
 * Extract NALs from Annex-B byte stream.
 * Each returned vector<char> contains one NALunit including its start code (0x000001 or 0x00000001).
 */
std::vector<std::vector<char>> Client::extractAnnexBNals(const std::vector<char> &data) {
    std::vector<std::vector<char>> nals;
    size_t i = 0;
    size_t sz = data.size();

    auto is_start3 = [&](size_t pos) {
        return pos + 3 < sz &&
               (unsigned char)data[pos] == 0x00 &&
               (unsigned char)data[pos+1] == 0x00 &&
               (unsigned char)data[pos+2] == 0x01;
    };
    auto is_start4 = [&](size_t pos) {
        return pos + 4 < sz &&
               (unsigned char)data[pos] == 0x00 &&
               (unsigned char)data[pos+1] == 0x00 &&
               (unsigned char)data[pos+2] == 0x00 &&
               (unsigned char)data[pos+3] == 0x01;
    };

    // find first start code
    size_t pos = 0;
    while (pos < sz) {
        size_t sc_pos = std::string::npos;
        size_t sc_len = 0;
        // find next start code
        for (size_t p = pos; p + 3 < sz; ++p) {
            if (is_start4(p)) { sc_pos = p; sc_len = 4; break; }
            if (is_start3(p)) { sc_pos = p; sc_len = 3; break; }
        }
        if (sc_pos == std::string::npos) break;
        // determine next start code after sc_pos+sc_len
        size_t next_sc = std::string::npos;
        for (size_t p = sc_pos + sc_len; p + 3 < sz; ++p) {
            if (is_start4(p)) { next_sc = p; break; }
            if (is_start3(p)) { next_sc = p; break; }
        }
        if (next_sc == std::string::npos) {
            // last NAL: include until end
            std::vector<char> nal(data.begin() + sc_pos, data.end());
            nals.push_back(std::move(nal));
            break;
        } else {
            std::vector<char> nal(data.begin() + sc_pos, data.begin() + next_sc);
            nals.push_back(std::move(nal));
            pos = next_sc;
        }
    }
    return nals;
}

bool Client::tcpStreamRun(sock_t sock) {
    // Read entire file into memory (simpler and robust for test streams).
    std::ifstream infile(h264File_, std::ios::binary);
    if (!infile.is_open()) {
        LOG_GEN_ERROR("Failed to open file '{}'", h264File_);
        return false;
    }
    infile.seekg(0, std::ios::end);
    std::streamsize fsize = infile.tellg();
    infile.seekg(0, std::ios::beg);
    if (fsize <= 0) {
        LOG_GEN_ERROR("Empty or inaccessible file '{}'", h264File_);
        return false;
    }
    std::vector<char> fileData;
    fileData.resize((size_t)fsize);
    infile.read(fileData.data(), fsize);
    infile.close();

    auto nals = extractAnnexBNals(fileData);
    if (nals.empty()) {
        LOG_GEN_ERROR("No NAL units found in '{}'. Is it raw H.264 (Annex-B)?", h264File_);
        return false;
    }
    LOG_GEN_INFO("Extracted {} NAL units from {}", nals.size(), h264File_);

    // Ensure connection established (wait for connect completion on non-blocking socket)
#ifdef __linux__
    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLOUT;
    int pret = poll(&pfd, 1, 5000);
    if (pret <= 0) {
        LOG_GEN_ERROR("connect timeout or error");
        return false;
    } else {
        int err = 0; socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        if (err != 0) {
            LOG_GEN_ERROR("connect failed err={}", err);
            return false;
        }
    }
#else
    // Windows - use select to check connection status
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    timeval timeout{};
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int selret = select(0, NULL, &writefds, NULL, &timeout);
    if (selret <= 0) {
        LOG_GEN_ERROR("connect timeout or error");
        return false;
    } else {
        int error = 0;
        int error_size = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &error_size) != 0 || error != 0) {
            LOG_GEN_ERROR("connect failed err={}", error);
            return false;
        }
    }
#endif

    LOG_GEN_INFO("Connected to server {}:{}", host_, tcpPort_);

    StubFec encoder;

    // Send NAL units in order; if loop_ is true, repeat indefinitely.
    do {
        for (size_t i = 0; i < nals.size(); ++i) {
            const auto &nal = nals[i];
            uint16_t fec_k = 10;
            uint16_t fec_m = 2;
            uint16_t flags = 0;
            auto packet = encoder.encode_with_header(clientId_, packetSeq_++, fec_k, fec_m, flags, nal.data(), nal.size());

            // send robustly (handle EAGAIN)
            size_t to_send = packet.size();
            size_t sent = 0;
            while (sent < to_send) {
#ifdef __linux__
                ssize_t n = send(sock, packet.data() + sent, (int)(to_send - sent), MSG_NOSIGNAL);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        pollfd waitfd{};
                        waitfd.fd = sock;
                        waitfd.events = POLLOUT;
                        if (poll(&waitfd, 1, 3000) <= 0) {
                            LOG_NET_INFO("poll timeout during send");
                            return false;
                        }
                        continue;
                    } else {
                        LOG_NET_INFO("send failed errno={}", errno);
                        return false;
                    }
                }
                sent += (size_t)n;
#else
                int n = send(sock, packet.data() + sent, (int)(to_send - sent), 0);
                if (n == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        continue;
                    } else {
                        LOG_NET_INFO("send failed err={}", err);
                        return false;
                    }
                }
                sent += (size_t)n;
#endif
            }
            LOG_VIDEO_INFO("video_send: client_id={} seq={} nal_index={} nal_bytes={}", clientId_, packetSeq_-1, (unsigned)i, (uint32_t)nal.size());

            // Small delay between NAL units to prevent overwhelming the server
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        if (!loop_) break;
        // small sleep to avoid tight infinite loop saturating bandwidth in tests
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (loop_);

    LOG_GEN_INFO("Stream finished, closing");
    return true;
}

bool Client::run() {
    sock_t tcpSock = INVALID_SOCK;
    sock_t udpSock = INVALID_SOCK;
    if (!initAndConnect(tcpSock, udpSock)) return false;

    uint32_t seq = 1;
    if (sendUdpRegister(udpSock, seq++)) {
        uint32_t assigned = 0;
        if (receiveUdpRegisterResp(udpSock, assigned, 2000)) {
            clientId_ = assigned;
            LOG_GEN_INFO("Assigned client id={}", clientId_);
        } else {
            LOG_GEN_WARN("No UDP register response - continuing with id=0");
        }
    } else {
        LOG_GEN_WARN("UDP register send failed");
    }

    bool ok = tcpStreamRun(tcpSock);

    closeSocketLocal(tcpSock);
    closeSocketLocal(udpSock);
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_GEN_INFO("Client exiting");
    return ok;
}
