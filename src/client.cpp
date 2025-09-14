/*
* @license
* (C) zachbabanov
*
*/

#include <encoder.hpp>
#include <client.hpp>
#include <common.hpp>
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

Client::Client(const std::string &host, int port, const std::string &h264File, bool loop, bool use_fec)
        : host_(host), tcpPort_(port), udpPort_(port + 1), h264File_(h264File), loop_(loop),
          clientId_(0), packetSeq_(1),
          use_fec_(use_fec),
          bitrate_kbps_(0), tokens_(0.0), last_fill_(std::chrono::steady_clock::now()),
          stop_tcp_listener_(false)
{}

Client::~Client() {
    stopTcpListener();
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

    // Create TCP socket for commands
    addrinfo hints{};
    addrinfo *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host_.c_str(), std::to_string(tcpPort_).c_str(), &hints, &res) != 0) {
        LOG_GEN_ERROR("getaddrinfo failed for {}:{}", host_, tcpPort_);
        return false;
    }

    sock_t tcpSock = INVALID_SOCK;
    for (addrinfo *rp = res; rp; rp = rp->ai_next) {
        tcpSock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (tcpSock == INVALID_SOCK) continue;

        setSocketNonBlocking(tcpSock);
        enableSocketKeepAliveAndNoDelay(tcpSock);

        int r = connect(tcpSock, rp->ai_addr, (int)rp->ai_addrlen);
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
        closeSocket(tcpSock);
        tcpSock = INVALID_SOCK;
    }
    freeaddrinfo(res);
    if (tcpSock == INVALID_SOCK) {
        LOG_GEN_ERROR("Failed to create/connect TCP socket");
        return false;
    }
    outTcpSock = tcpSock;
    LOG_NET_INFO("TCP socket initialized to {}:{}", host_, tcpPort_);

    // Create UDP socket for video
    sock_t udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udp == INVALID_SOCK) {
        LOG_GEN_ERROR("UDP socket creation failed");
        return false;
    }

    // Increase UDP buffer sizes (best-effort)
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(udp, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf));

    setSocketNonBlocking(udp);
    outUdpSock = udp;
    return true;
}

void Client::closeSocketLocal(sock_t s) {
    closeSocket(s);
}

bool Client::sendTcpRegister(sock_t tcpSock, uint32_t seq) {
    UdpHeader hdr{};
    hdr.client_id = hton_u32(0);
    hdr.command_id = hton_u16(CMD_REGISTER);
    hdr.flags = 0;
    hdr.seq = hton_u32(seq);

    // send fully (small message)
    ssize_t total = 0;
    const char *buf = (const char*)&hdr;
    size_t tosend = sizeof(hdr);
    while (total < (ssize_t)tosend) {
        ssize_t n = send(tcpSock, buf + total, (int)(tosend - total), 0);
        if (n <= 0) {
#ifdef __linux__
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                pollfd pfd{tcpSock, POLLOUT, 0};
                poll(&pfd, 1, 1000);
                continue;
            }
#endif
            LOG_NET_INFO("send register failed");
            return false;
        }
        total += n;
    }
    LOG_NET_INFO("TCP register sent seq={}", seq);
    return true;
}

bool Client::receiveTcpRegisterResp(sock_t tcpSock, uint32_t &assigned, int timeoutMs) {
#ifdef __linux__
    pollfd pfd{};
    pfd.fd = tcpSock;
    pfd.events = POLLIN;
    int r = poll(&pfd, 1, timeoutMs);
    if (r <= 0) return false;
    if (pfd.revents & POLLIN) {
        char buf[512];
        int n = recv(tcpSock, buf, sizeof(buf), 0);
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
    FD_SET(tcpSock, &rfds);
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    int r = select((int)(tcpSock + 1), &rfds, nullptr, nullptr, &tv);
    if (r <= 0) return false;
    if (FD_ISSET(tcpSock, &rfds)) {
        char buf[512];
        int n = recv(tcpSock, buf, sizeof(buf), 0);
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

void Client::startTcpListener(project::common::sock_t tcpSock) {
    stop_tcp_listener_.store(false);
    tcp_listener_thread_ = std::thread([this, tcpSock]() { tcpListenerLoop(tcpSock); });
}

void Client::stopTcpListener() {
    stop_tcp_listener_.store(true);
    if (tcp_listener_thread_.joinable()) tcp_listener_thread_.join();
}

void Client::tcpListenerLoop(project::common::sock_t tcpSock) {
    LOG_GEN_INFO("TCP listener thread started for client (fd={})", (long long)tcpSock);
    while (!stop_tcp_listener_.load()) {
        char buf[512];
#ifdef __linux__
        pollfd pfd{};
        pfd.fd = tcpSock;
        pfd.events = POLLIN;
        int pret = poll(&pfd, 1, 200);
        if (pret <= 0) continue;
        int n = recv(tcpSock, buf, sizeof(buf), 0);
#else
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tcpSock, &rfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 200000; // 200ms
        int r = select((int)(tcpSock + 1), &rfds, nullptr, nullptr, &tv);
        if (r <= 0) continue;
        int n = recv(tcpSock, buf, sizeof(buf), 0);
#endif
        if (n <= 0) {
            if (n == 0) {
                LOG_NET_INFO("TCP connection closed by server");
                stop_tcp_listener_.store(true);
            }
            continue;
        }
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
                LOG_FEC_INFO("Received CMD_SET_BITRATE from server: set bitrate={} kbps", kbps);
            } else {
                LOG_FEC_WARN("Received CMD_SET_BITRATE with empty payload");
            }
        } else if (ntoh_u16(hdr.command_id) == CMD_REGISTER_RESP) {
            // ignore (handled elsewhere)
        } else {
            // ignore other commands
            LOG_NET_INFO("TCP listener got unknown cmd={}", ntoh_u16(hdr.command_id));
        }
    }
    LOG_GEN_INFO("TCP listener thread exiting");
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
    const double sleep_chunk = 0.001; // 1ms
    double slept = 0.0;
    while (slept < wait_sec) {
        if (stop_tcp_listener_.load()) break;
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

bool Client::udpStreamRun(sock_t udpSock) {
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

    // Set up server address for UDP
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, host_.c_str(), &serverAddr.sin_addr);
    serverAddr.sin_port = htons(udpPort_);

    StubFec encoder;

    // Max payload per UDP fragment (leave room for our fragment header)
    const size_t frag_hdr_size = sizeof(common::UdpVideoFragmentHeader);
    const size_t max_fragment_payload = (MAX_UDP_PACKET_SIZE > frag_hdr_size) ? (MAX_UDP_PACKET_SIZE - frag_hdr_size) : 256;

    LOG_GEN_INFO("UDP streaming to {}:{} use_fec={}", host_, udpPort_, use_fec_ ? "yes" : "no");

    // Send NAL units in order; if loop_ is true, repeat indefinitely.
    do {
        for (size_t i = 0; i < nals.size(); ++i) {
            auto nal = nals[i]; // copy, because we might resize it

            // Determine nal type for pts
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

            // Choose FEC parameters depending on mode
            uint16_t fec_k = 1;
            uint16_t fec_m = 0;
            uint16_t flags = 0;

            if (use_fec_) {
                // Estimate number of 255-byte symbols required for this nal
                // (this mirrors the earlier heuristic). Keep m small (e.g. 2).
                constexpr size_t SYMBOL_SIZE = 255;
                fec_k = (uint16_t)((nal.size() + SYMBOL_SIZE - 1) / SYMBOL_SIZE);
                if (fec_k == 0) fec_k = 1;
                // keep a modest parity count but don't exceed available room
                fec_m = 2;
            } else {
                // pass-through: single data symbol, no parity
                fec_k = 1;
                fec_m = 0;
            }

            // Build encoded packet (header + encoded payload)
            auto packet = encoder.encode_with_header(clientId_, packetSeq_++, fec_k, fec_m, flags,
                                                     pts,
                                                     nal.data(), nal.size());

            if (packet.empty()) {
                LOG_FEC_ERROR("Encoder returned empty packet for nal idx {} size {}", i, nal.size());
                continue;
            }

            // Fragment the encoded packet into UDP datagrams with our fragment header
            size_t total_len = packet.size();
            if (total_len > MAX_UDP_REASSEMBLY_BYTES) {
                LOG_FEC_WARN("Encoded packet too large ({} bytes) - skipping", total_len);
                continue;
            }

            uint16_t total_frags = (uint16_t)((total_len + max_fragment_payload - 1) / max_fragment_payload);
            if (total_frags == 0) total_frags = 1;

            size_t offset = 0;
            for (uint16_t frag_idx = 0; frag_idx < total_frags; ++frag_idx) {
                size_t remaining = total_len - offset;
                size_t this_payload = std::min(remaining, max_fragment_payload);

                // Build fragment header
                common::UdpVideoFragmentHeader vhdr{};
                vhdr.client_id = hton_u32(clientId_);
                vhdr.packet_seq = hton_u32(packetSeq_ - 1);
                vhdr.total_packet_len = hton_u32((uint32_t)total_len);
                vhdr.frag_offset = hton_u32((uint32_t)offset);
                vhdr.frag_payload_len = hton_u16((uint16_t)this_payload);
                vhdr.total_frags = hton_u16(total_frags);
                vhdr.frag_index = hton_u16(frag_idx);
                vhdr.flags = hton_u16(0);
                vhdr.pts = hton_u64(pts);

                std::vector<char> out;
                out.reserve(sizeof(vhdr) + this_payload);
                out.insert(out.end(), (char*)&vhdr, ((char*)&vhdr) + sizeof(vhdr));
                out.insert(out.end(), packet.data() + offset, packet.data() + offset + this_payload);

                // Pacing: ensure we don't exceed requested bitrate
                pace_before_send(out.size());

                // Send via UDP (handle EAGAIN)
                ssize_t sent_total = 0;
                const char *sendbuf = out.data();
                size_t tosend = out.size();
                int retry = 0;
                while (sent_total < (ssize_t)tosend) {
                    ssize_t rc = sendto(udpSock, sendbuf + sent_total, (int)(tosend - sent_total), 0,
                                        (sockaddr*)&serverAddr, sizeof(serverAddr));
                    if (rc < 0) {
#ifdef __linux__
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // wait a bit and retry
                            pollfd pfd{udpSock, POLLOUT, 0};
                            poll(&pfd, 1, 50);
                            retry++;
                            if (retry > 20) {
                                LOG_NET_DEBUG("sendto repeatedly EAGAIN, aborting fragment");
                                break;
                            }
                            continue;
                        }
#else
                        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            retry++;
            if (retry > 50) break;
            continue;
        }
#endif
                        LOG_NET_DEBUG("sendto failed: {}", strerror(errno));
                        break;
                    }
                    sent_total += rc;
                }
                if (sent_total != (ssize_t)tosend) {
                    LOG_NET_DEBUG("Fragment send incomplete ({}/{})", sent_total, tosend);
                    // best-effort: continue
                }

                LOG_FEC_DEBUG("video_send_frag: client_id={} seq={} frag={}/{} off={} len={} pts={} use_fec={}",
                              clientId_, packetSeq_-1, frag_idx, total_frags, offset, this_payload, pts, use_fec_ ? 1 : 0);

                offset += this_payload;
            } // frag loop

            // Small gap between NALs to avoid saturating link
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
        } // for nals

        if (!loop_) break;
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
    if (sendTcpRegister(tcpSock, seq++)) {
        uint32_t assigned = 0;
        if (receiveTcpRegisterResp(tcpSock, assigned, 2000)) {
            clientId_ = assigned;
            LOG_GEN_INFO("Assigned client id={}", clientId_);
        } else {
            LOG_GEN_ERROR("No TCP register response received");
            closeSocketLocal(tcpSock);
            closeSocketLocal(udpSock);
            return false;
        }
    } else {
        LOG_GEN_ERROR("TCP register send failed");
        closeSocketLocal(tcpSock);
        closeSocketLocal(udpSock);
        return false;
    }

    // start TCP listener thread to receive runtime commands (e.g. set bitrate)
    startTcpListener(tcpSock);

    bool ok = udpStreamRun(udpSock);

    // shutdown TCP listener first
    stopTcpListener();

    closeSocketLocal(tcpSock);
    closeSocketLocal(udpSock);
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_GEN_INFO("Client exiting");
    return ok;
}
