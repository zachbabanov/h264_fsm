/*
* @license
* (C) zachbabanov
*
*/

#include <client.hpp>
#include <common.hpp>
#include <encoder.hpp>
#include <logger.hpp>

#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>

#ifdef __linux__
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

using namespace project::client;
using namespace project::common;
using namespace project::fec;
using namespace project::log;

Client::Client(const std::string &host, int port, const std::string &h264File, bool loop)
        : host_(host), tcpPort_(port), udpPort_(port + 1), h264File_(h264File), loop_(loop),
          clientId_(0), packetSeq_(1),
          bitrate_kbps_(0), tokens_(0.0), last_fill_(std::chrono::steady_clock::now()),
          stop_udp_listener_(false)
{}

Client::~Client() {
    stopUdpListener();
}

void Client::set_initial_bitrate(uint32_t kbps) {
    bitrate_kbps_.store(kbps);
    {
        std::lock_guard<std::mutex> lk(rate_mtx_);
        tokens_ = 0.0;
        last_fill_ = std::chrono::steady_clock::now();
    }
    LOG_FEC_INFO("Initial bitrate set to {} kbps", kbps);
}

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

    // Create UDP socket and bind to ephemeral local port so we can receive commands
    sock_t udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udp == INVALID_SOCK) {
        LOG_GEN_ERROR("UDP socket creation failed");
        return false;
    }

    sockaddr_in bindaddr{};
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_addr.s_addr = INADDR_ANY;
    bindaddr.sin_port = htons(0); // ephemeral
    if (bind(udp, (sockaddr*)&bindaddr, sizeof(bindaddr)) < 0) {
        LOG_NET_INFO("UDP bind failed (will still try) errno={}", errno);
        // Not fatal — continue
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

void Client::startUdpListener(project::common::sock_t udpSock) {
    stop_udp_listener_.store(false);
    udp_listener_thread_ = std::thread([this, udpSock]() { udpListenerLoop(udpSock); });
}

void Client::stopUdpListener() {
    stop_udp_listener_.store(true);
    if (udp_listener_thread_.joinable()) udp_listener_thread_.join();
}

void Client::udpListenerLoop(project::common::sock_t udpSock) {
    LOG_GEN_INFO("UDP listener thread started for client (fd={})", (long long)udpSock);
    while (!stop_udp_listener_.load()) {
        char buf[512];
        sockaddr_in src{};
        socklen_t sl = sizeof(src);
#ifdef __linux__
        pollfd pfd{};
        pfd.fd = udpSock;
        pfd.events = POLLIN;
        int pret = poll(&pfd, 1, 200);
        if (pret <= 0) continue;
        int n = recvfrom(udpSock, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
#else
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(udpSock, &rfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 200000; // 200ms
        int r = select((int)(udpSock + 1), &rfds, nullptr, nullptr, &tv);
        if (r <= 0) continue;
        int n = recvfrom(udpSock, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
#endif
        if (n <= 0) continue;
        if ((size_t)n < sizeof(UdpHeader)) continue;
        UdpHeader hdr;
        memcpy(&hdr, buf, sizeof(hdr));
        uint16_t cmd = ntoh_u16(hdr.command_id);
        if (cmd == CMD_SET_BITRATE) {
            // payload expected to contain uint32_t kbps in network order
            if ((size_t)n >= sizeof(hdr) + sizeof(uint32_t)) {
                uint32_t net_kbps = 0;
                memcpy(&net_kbps, buf + sizeof(hdr), sizeof(uint32_t));
                uint32_t kbps = ntohl(net_kbps);
                bitrate_kbps_.store(kbps);
                // Reinitialize token bucket to avoid huge burst immediately
                {
                    std::lock_guard<std::mutex> lk(rate_mtx_);
                    tokens_ = 0.0;
                    last_fill_ = std::chrono::steady_clock::now();
                }
                LOG_FEC_INFO("Received CMD_SET_BITRATE from {}: set bitrate={} kbps", inet_ntoa(src.sin_addr), kbps);
            } else {
                LOG_FEC_WARN("Received CMD_SET_BITRATE with empty payload");
            }
        } else if (ntoh_u16(hdr.command_id) == CMD_REGISTER_RESP) {
            // ignore (handled elsewhere)
        } else {
            // ignore other commands
            LOG_NET_INFO("UDP listener got unknown cmd={}", ntoh_u16(hdr.command_id));
        }
    }
    LOG_GEN_INFO("UDP listener thread exiting");
}

/**
 * Token-bucket pacing before sending bytes. Blocks (sleep) if needed to respect bitrate_kbps_.
 */
void Client::pace_before_send(size_t bytes) {
    uint32_t kbps = bitrate_kbps_.load();
    if (kbps == 0) return; // unlimited

    double rate_bytes_per_sec = (double)kbps * 1000.0 / 8.0; // kbps->bytes/sec

    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(rate_mtx_);
    double elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - last_fill_).count();
    if (elapsed > 0) {
        tokens_ += rate_bytes_per_sec * elapsed;
        // cap tokens to 2 seconds worth to allow short bursts
        double max_tokens = rate_bytes_per_sec * 2.0;
        if (tokens_ > max_tokens) tokens_ = max_tokens;
        last_fill_ = now;
    }

    if (tokens_ >= (double)bytes) {
        tokens_ -= (double)bytes;
        return;
    }

    // Need to wait for (bytes - tokens_) / rate_seconds
    double need = (double)bytes - tokens_;
    double wait_sec = need / rate_bytes_per_sec;
    if (wait_sec < 0) wait_sec = 0;
    // Sleep in small chunks to keep responsive to possible bitrate changes
    const double sleep_chunk = 0.01; // 10ms
    double slept = 0.0;
    while (slept < wait_sec) {
        if (stop_udp_listener_.load()) break;
        double to_sleep = std::min(sleep_chunk, wait_sec - slept);
#ifdef __linux__
        std::this_thread::sleep_for(std::chrono::duration<double>(to_sleep));
#else
        std::this_thread::sleep_for(std::chrono::duration<double>(to_sleep));
#endif
        slept += to_sleep;
        // refill tokens during sleep
        auto now2 = std::chrono::steady_clock::now();
        double elapsed2 = std::chrono::duration_cast<std::chrono::duration<double>>(now2 - last_fill_).count();
        if (elapsed2 > 0) {
            tokens_ += rate_bytes_per_sec * elapsed2;
            double max_tokens = rate_bytes_per_sec * 2.0;
            if (tokens_ > max_tokens) tokens_ = max_tokens;
            last_fill_ = now2;
        }
        // if tokens suffice now, consume and return
        if (tokens_ >= (double)bytes) {
            tokens_ -= (double)bytes;
            return;
        }
    }
    // final attempt
    if (tokens_ >= (double)bytes) {
        tokens_ -= (double)bytes;
    } else {
        // consume whatever available and continue (we waited already)
        tokens_ = 0.0;
    }
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
            // Determine nal type for pts (we keep previous logic)
            size_t sc_len = 0;
            if (nal.size() >= 4 && (unsigned char)nal[0] == 0x00 && (unsigned char)nal[1] == 0x00 &&
                (unsigned char)nal[2] == 0x00 && (unsigned char)nal[3] == 0x01) {
                sc_len = 4;
            } else if (nal.size() >= 3 && (unsigned char)nal[0] == 0x00 && (unsigned char)nal[1] == 0x00 &&
                       (unsigned char)nal[2] == 0x01) {
                sc_len = 3;
            } else {
                sc_len = 0;
            }

            int nal_type = -1;
            if (sc_len > 0 && nal.size() > sc_len) {
                unsigned char nal_byte = (unsigned char)nal[sc_len];
                nal_type = nal_byte & 0x1F;
            }

            bool is_vcl = (nal_type == 1 || nal_type == 5);
            // We'll use a simple frame_count derived from VCL presence
            static uint64_t frame_count = 0;
            uint64_t pts = frame_count * 40;
            if (is_vcl) frame_count++;

            uint16_t fec_k = 10;
            uint16_t fec_m = 2;
            uint16_t flags = 0;
            auto packet = encoder.encode_with_header(clientId_, packetSeq_++, fec_k, fec_m, flags,
                                                     pts,
                                                     nal.data(), nal.size());

            // Pacing: ensure we don't exceed requested bitrate
            pace_before_send(packet.size());

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
            LOG_FEC_DEBUG("video_send: client_id={} seq={} nal_index={} nal_bytes={} nal_type={} pts={}",
                          clientId_, packetSeq_-1, (unsigned)i, (uint32_t)nal.size(), nal_type, pts);

            // Small delay between NAL units to prevent overwhelming the server
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
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

    // start UDP listener thread to receive runtime commands (e.g. set bitrate)
    startUdpListener(udpSock);

    bool ok = tcpStreamRun(tcpSock);

    // shutdown udp listener first
    stopUdpListener();

    closeSocketLocal(tcpSock);
    closeSocketLocal(udpSock);
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_GEN_INFO("Client exiting");
    return ok;
}
