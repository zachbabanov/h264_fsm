/*
* @license
* (C) zachbabanov
*
*/

#include <encoder.hpp>
#include <server.hpp>
#include <common.hpp>
#include <logger.hpp>

#include <unordered_map>
#include <cstring>
#include <cerrno>
#include <chrono>

#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#else
#ifdef _WIN32
 #include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif
#endif

using namespace project::server;
using namespace project::common;
using namespace project::fec;
using namespace project::log;

/**
 * analyze_nal_types:
 *  Scans Annex-B formatted payload (may contain 1+ NALs) and sets flags
 *  hasSps/hasPps/hasIdr when finds nal_unit_type == 7/8/5 respectively.
 */
void Server::analyze_nal_types(const std::vector<char> &payload, bool &hasSps, bool &hasPps, bool &hasIdr) {
    hasSps = false;
    hasPps = false;
    hasIdr = false;
    size_t sz = payload.size();
    auto is_start4 = [&](size_t p) {
        return p + 3 < sz &&
               (unsigned char)payload[p] == 0x00 &&
               (unsigned char)payload[p+1] == 0x00 &&
               (unsigned char)payload[p+2] == 0x00 &&
               (unsigned char)payload[p+3] == 0x01;
    };
    auto is_start3 = [&](size_t p) {
        return p + 2 < sz &&
               (unsigned char)payload[p] == 0x00 &&
               (unsigned char)payload[p+1] == 0x00 &&
               (unsigned char)payload[p+2] == 0x01;
    };

    size_t p = 0;
    while (p + 3 < sz) {
        size_t sc = std::string::npos;
        size_t sc_len = 0;
        // find start code
        for (size_t i = p; i + 2 < sz; ++i) {
            if (is_start4(i)) { sc = i; sc_len = 4; break; }
            if (is_start3(i)) { sc = i; sc_len = 3; break; }
        }
        if (sc == std::string::npos) break;
        size_t nal_header = sc + sc_len;
        if (nal_header >= sz) break;
        unsigned char nal_byte = (unsigned char)payload[nal_header];
        unsigned int nal_type = nal_byte & 0x1F;
        if (nal_type == 7) hasSps = true;
        if (nal_type == 8) hasPps = true;
        if (nal_type == 5) hasIdr = true;
        // move p to search next start code after nal_header
        p = nal_header + 1;
    }
}

Server::Server(int tcpPort, const std::string &playerCmd)
        : tcpPort_(tcpPort),
          udpPort_(tcpPort + 1),
          tcpListenSocket_(INVALID_SOCK),
          udpVideoSocket_(INVALID_SOCK),
          nextClientId_(1),
          playerCmd_(playerCmd)
#ifdef __linux__
        , epollFd_(-1)
#endif
{
}

Server::~Server() {
#ifdef __linux__
    if (epollFd_ >= 0) close(epollFd_);
#endif
    if (tcpListenSocket_ != INVALID_SOCK) closeSocket(tcpListenSocket_);
    if (udpVideoSocket_ != INVALID_SOCK) closeSocket(udpVideoSocket_);
#ifdef _WIN32
    WSACleanup();
#endif
}

bool Server::setupListenSocket() {
#ifdef _WIN32
    // Initialize Winsock — must be done before socket() on Windows
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        LOG_GEN_ERROR("WSAStartup failed");
        return false;
    }
#endif

    tcpListenSocket_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (tcpListenSocket_ == INVALID_SOCK) {
        LOG_GEN_ERROR("Failed to create listen socket");
        return false;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(tcpListenSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(tcpListenSocket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(tcpPort_);

    if (bind(tcpListenSocket_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_GEN_ERROR("bind failed on port {}", tcpPort_);
        closeSocket(tcpListenSocket_);
        return false;
    }

    if (setSocketNonBlocking(tcpListenSocket_) < 0) {
        LOG_GEN_ERROR("set nonblocking failed for listen socket");
        closeSocket(tcpListenSocket_);
        return false;
    }

    if (listen(tcpListenSocket_, 64) < 0) {
        LOG_GEN_ERROR("listen failed");
        closeSocket(tcpListenSocket_);
        return false;
    }

    LOG_GEN_INFO("Listening on TCP port {}", tcpPort_);
    return true;
}

bool Server::start() {
    if (!setupListenSocket()) return false;

#ifdef __linux__
    epollFd_ = epoll_create1(0);
    if (epollFd_ < 0) {
        perror("epoll_create1");
        return false;
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = tcpListenSocket_;
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, tcpListenSocket_, &ev) < 0) {
        perror("epoll_ctl add listen");
        return false;
    }

    // UDP for video
    udpVideoSocket_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udpVideoSocket_ == INVALID_SOCK) { perror("udp socket"); return false; }

    // Increase UDP buffer sizes
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(udpVideoSocket_, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf));

    sockaddr_in uaddr{};
    uaddr.sin_family = AF_INET;
    uaddr.sin_addr.s_addr = INADDR_ANY;
    uaddr.sin_port = htons(udpPort_);
    if (bind(udpVideoSocket_, (sockaddr*)&uaddr, sizeof(uaddr)) < 0) { perror("udp bind"); closeSocket(udpVideoSocket_); return false; }
    setSocketNonBlocking(udpVideoSocket_);
    ev.events = EPOLLIN;
    ev.data.fd = udpVideoSocket_;
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, udpVideoSocket_, &ev) < 0) { perror("epoll_ctl add udp"); closeSocket(udpVideoSocket_); return false; }
    LOG_GEN_INFO("UDP video listening on port {}", udpPort_);
#else
    // Windows: create UDP socket for video
    udpVideoSocket_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udpVideoSocket_ == INVALID_SOCK) {
        LOG_GEN_ERROR("Failed to create UDP video socket on Windows");
        return false;
    }

    // Increase UDP buffer sizes
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(udpVideoSocket_, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf));

    sockaddr_in uaddr{};
    uaddr.sin_family = AF_INET;
    uaddr.sin_addr.s_addr = INADDR_ANY;
    uaddr.sin_port = htons(udpPort_);
    if (bind(udpVideoSocket_, (sockaddr*)&uaddr, sizeof(uaddr)) == SOCKET_ERROR) {
        LOG_GEN_ERROR("UDP video bind failed on Windows");
        closeSocket(udpVideoSocket_);
        udpVideoSocket_ = INVALID_SOCK;
        return false;
    }
    setSocketNonBlocking(udpVideoSocket_);
    LOG_GEN_INFO("UDP video listening on port {}", udpPort_);
    LOG_GEN_INFO("Using WSAPoll loop on Windows");
#endif

    LOG_GEN_INFO("Server started on TCP port {} with player '{}'", tcpPort_, playerCmd_);
    return true;
}

void Server::runLoop() {
#ifdef __linux__
    std::vector<epoll_event> events(64);
    while (true) {
        int n = epoll_wait(epollFd_, events.data(), (int)events.size(), 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;
            if (fd == tcpListenSocket_) {
                acceptNewConnections();
            } else if (fd == udpVideoSocket_) {
                handleUdpVideoEvent(udpVideoSocket_);
            } else {
                // check if this is a player write-fd
                auto pit = playerFdToClientFd_.find(fd);
                if (pit != playerFdToClientFd_.end()) {
                    handlePlayerFdEvent(fd);
                } else {
                    if (clients_.count(fd)) {
                        handleTcpEvent(fd, ev);
                    }
                }
            }
        }

        // Process frame queues and flush player buffers for all clients regularly
        for (auto &kv : clients_) {
            processFrameQueue(kv.second);
            flushPlayerBuffer(kv.second);
        }

        // GC for incomplete UDP reassembly (remove old InProgress)
        // storm prevention: remove entries older than 2000ms
        {
            static std::vector<uint64_t> to_erase;
            to_erase.clear();
            auto now = std::chrono::steady_clock::now();
            for (auto &kv : inprogress_map_) {
                InProgress &ip = kv.second;
                auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - ip.first_seen).count();
                if (age_ms > 2000) {
                    LOG_FEC_WARN("Dropping incomplete packet client_id={} seq={} age_ms={} received_bytes={}/{}",
                                 ip.client_id, ip.packet_seq, (int)age_ms, (int)ip.received_bytes, (int)ip.total_packet_len);
                    to_erase.push_back(kv.first);
                }
            }
            for (uint64_t k : to_erase) inprogress_map_.erase(k);
        }
    }
#else
    // Windows WSAPoll loop (unchanged)...
    while (true) {
        std::vector<WSAPOLLFD> fds;
        WSAPOLLFD lfd{};
        lfd.fd = tcpListenSocket_;
        lfd.events = POLLIN;
        fds.push_back(lfd);

        WSAPOLLFD ufd{};
        ufd.fd = udpVideoSocket_;
        ufd.events = POLLIN;
        fds.push_back(ufd);

        // Add clients to pollset
        for (auto &kv : clients_) {
            WSAPOLLFD cfd{};
            cfd.fd = kv.first;
            cfd.events = POLLIN;
            fds.push_back(cfd);
        }

        int timeoutMs = 100; // shorter timeout to frequently service playback
        int ret = WSAPoll(fds.data(), (ULONG)fds.size(), timeoutMs);
        if (ret == SOCKET_ERROR) {
            LOG_GEN_ERROR("WSAPoll failed");
            break;
        }
        if (ret == 0) {
            // timeout -> we still must drive playback
        } else {
            // index 0 = tcpListenSocket, 1 = udpVideoSocket, rest = clients in same iteration order
            if (!fds.empty()) {
                if (fds[0].revents & POLLIN) acceptNewConnections();
                if (fds.size() > 1 && (fds[1].revents & POLLIN)) handleUdpVideoEvent(udpVideoSocket_);
            }

            // client events start from index 2
            size_t idx = 2;
            for (auto &kv : clients_) {
                if (idx >= fds.size()) break;
                WSAPOLLFD &cfd = fds[idx++];
                if (cfd.revents & POLLIN) {
                    handleTcpEvent(kv.first, cfd.revents);
                }
                // if there are errors, mark closing
                if (cfd.revents & (POLLERR | POLLHUP)) {
                    kv.second.state = State::CLOSING;
                    handleTcpEvent(kv.first, cfd.revents);
                }
            }
        }

        // Always process frame queues AND flush buffers for all clients (important for timing)
        for (auto &kv : clients_) {
            processFrameQueue(kv.second);
            flushPlayerBuffer(kv.second);
            if (kv.second.state == State::CLOSING) {
                closeConnection(kv.first);
                // iterator invalidation: break and restart loop in next iteration
                break;
            }
        }

        // GC for incomplete UDP reassembly (Windows)
        {
            static std::vector<uint64_t> to_erase;
            to_erase.clear();
            auto now = std::chrono::steady_clock::now();
            for (auto &kv : inprogress_map_) {
                InProgress &ip = kv.second;
                auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - ip.first_seen).count();
                if (age_ms > 2000) {
                    LOG_FEC_WARN("Dropping incomplete packet client_id={} seq={} age_ms={} received_bytes={}/{}",
                                 ip.client_id, ip.packet_seq, (int)age_ms, (int)ip.received_bytes, (int)ip.total_packet_len);
                    to_erase.push_back(kv.first);
                }
            }
            for (uint64_t k : to_erase) inprogress_map_.erase(k);
        }
    }
#endif
}

void Server::acceptNewConnections() {
    while (clients_.size() < MAX_CLIENTS) {
        sockaddr_in caddr{};
        socklen_t clen = sizeof(caddr);
        sock_t cfd = accept(tcpListenSocket_, (sockaddr*)&caddr, &clen);
        if (cfd == INVALID_SOCK) {
#ifdef __linux__
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("accept");
#else
            // On Windows, no more pending connections
            break;
#endif
        } else {
            if (setSocketNonBlocking(cfd) < 0) {
                LOG_GEN_ERROR("set nonblocking for client failed");
                closeSocket(cfd);
                break;
            }

            // enable keepalive and TCP_NODELAY for accepted socket
            enableSocketKeepAliveAndNoDelay(cfd);

            // create connection object
            Connection conn(cfd);

            // Launch player process with proper arguments for low latency
            std::vector<std::string> player_args = {
                    "-fflags", "nobuffer",
                    "-flags", "low_delay",
                    "-framedrop",
                    "-strict", "experimental",
                    "-f", "h264",
                    "-i", "-",
                    "-window_title", "Stream from client " + std::to_string(nextClientId_),
                    "-avioflags", "direct",
                    "-max_delay", "0",
                    "-probesize", "32",
                    "-analyzeduration", "0"
            };
            conn.player = project::player::PlayerProcess::launch(playerCmd_, player_args);
            if (!conn.player) {
                LOG_GEN_ERROR("Failed to launch player for client; closing socket {}", (long long)cfd);
                closeSocket(cfd);
                break;
            }
            conn.clientId = nextClientId_++;

#ifdef __linux__
            // register client fd in epoll
            epoll_event cev{};
            cev.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
            cev.data.fd = cfd;
            if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, cfd, &cev) < 0) {
                perror("epoll_ctl add client");
                conn.player->stop();
                closeSocket(cfd);
                continue;
            }
#endif
#ifdef __linux__
            int pfd = conn.player->get_write_fd();
            if (pfd >= 0) {
                epoll_event pev{};
                pev.events = EPOLLOUT | EPOLLET;
                pev.data.fd = pfd;
                if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, pfd, &pev) < 0) {
                    perror("epoll_ctl add playerfd");
                } else {
                    playerFdToClientFd_[pfd] = cfd;
                }
            }
#endif
            clients_.emplace(cfd, std::move(conn));
            char hostbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &caddr.sin_addr, hostbuf, sizeof(hostbuf));
            LOG_GEN_INFO("Accepted connection from {}:{} fd={} assigned_client_id={}", hostbuf, ntohs(caddr.sin_port), (long long)cfd, nextClientId_-1);
        }
    }
}

void Server::handleTcpEvent(sock_t fd, uint32_t events) {
    auto it = clients_.find(fd);
    if (it == clients_.end()) return;
    Connection &conn = it->second;

#ifdef __linux__
    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        conn.state = State::CLOSING;
    }
#else
    if (events & (POLLERR | POLLHUP)) {
        conn.state = State::CLOSING;
    }
#endif

    switch (conn.state) {
        case State::READING: {
#ifdef __linux__
            if (events & EPOLLIN) {
#else
                if (events & POLLIN) {
#endif
                char buf[BUFFER_SIZE];
                while (true) {
                    int n = (int)recv(fd, buf, sizeof(buf), 0);
                    if (n > 0) {
                        conn.inBuffer.append(buf, buf + n);

                        // Process TCP commands (control messages)
                        while (conn.inBuffer.size() >= sizeof(UdpHeader)) {
                            UdpHeader hdr;
                            memcpy(&hdr, conn.inBuffer.data(), sizeof(hdr));
                            uint16_t cmd = ntoh_u16(hdr.command_id);
                            uint32_t client_id = ntoh_u32(hdr.client_id);

                            if (cmd == CMD_REGISTER) {
                                // Assign a new client ID
                                uint32_t assigned_id = conn.clientId ? conn.clientId : nextClientId_++;
                                // Send registration response
                                UdpHeader resp{};
                                resp.client_id = hton_u32(assigned_id);
                                resp.command_id = hton_u16(CMD_REGISTER_RESP);
                                resp.flags = 0;
                                resp.seq = hton_u32(ntoh_u32(hdr.seq));

                                ssize_t sent = send(fd, (char*)&resp, sizeof(resp), 0);
                                if (sent > 0) {
                                    LOG_NET_INFO("Sent TCP register response to client, assigned id={}", assigned_id);
                                    conn.clientId = assigned_id;
                                } else {
                                    LOG_NET_INFO("Failed to send register response");
                                }

                                // Remove processed command
                                conn.inBuffer.erase(0, sizeof(UdpHeader));
                            } else if (cmd == CMD_SET_BITRATE) {
                                // Process bitrate change command (header+4 bytes payload)
                                if (conn.inBuffer.size() >= sizeof(UdpHeader) + sizeof(uint32_t)) {
                                    uint32_t net_kbps;
                                    memcpy(&net_kbps, conn.inBuffer.data() + sizeof(UdpHeader), sizeof(uint32_t));
                                    uint32_t kbps = ntohl(net_kbps);

                                    // Store the new bitrate (server-side action could be to forward to client via TCP later)
                                    LOG_FEC_INFO("Received SET_BITRATE from client {}: {} kbps", client_id, kbps);

                                    // Remove processed command
                                    conn.inBuffer.erase(0, sizeof(UdpHeader) + sizeof(uint32_t));
                                } else {
                                    // Not enough data yet
                                    break;
                                }
                            } else {
                                // Unknown command, skip the fixed header and continue
                                conn.inBuffer.erase(0, sizeof(UdpHeader));
                            }
                        }
                    } else if (n == 0) {
                        LOG_NET_INFO("peer closed connection fd={}", (long long)fd);
                        conn.state = State::CLOSING;
                        break;
                    } else {
#ifdef __linux__
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
#else
                            int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK) break;
#endif
                        LOG_NET_INFO("recv error on fd={} errno={}", (long long)fd, errno);
                        conn.state = State::CLOSING;
                        break;
                    }
                } // inner while
            }
            break;
        }
        case State::PROCESSING:
            // placeholder
            break;
        case State::WRITING:
            // handled by player fd events (linux)
            break;
        case State::CLOSING:
            closeConnection(fd);
            break;
        default:
            break;
    }
}

void Server::handleUdpVideoEvent(sock_t udpFd) {
    char buf[ (int)MAX_UDP_PACKET_SIZE ];
    sockaddr_in src{};
    socklen_t sl = sizeof(src);
    int n = recvfrom(udpFd, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
    if (n <= 0) return;

    if ((size_t)n < sizeof(common::UdpVideoFragmentHeader)) {
        LOG_NET_INFO("short video fragment from {}", inet_ntoa(src.sin_addr));
        return;
    }

    // Parse fragment header
    common::UdpVideoFragmentHeader vhdr;
    memcpy(&vhdr, buf, sizeof(vhdr));

    uint32_t client_id = ntoh_u32(vhdr.client_id);
    uint32_t packet_seq = ntoh_u32(vhdr.packet_seq);
    uint32_t total_packet_len = ntoh_u32(vhdr.total_packet_len);
    uint32_t frag_offset = ntoh_u32(vhdr.frag_offset);
    uint16_t frag_payload_len = ntoh_u16(vhdr.frag_payload_len);
    uint16_t total_frags = ntoh_u16(vhdr.total_frags);
    uint16_t frag_index = ntoh_u16(vhdr.frag_index);
    uint16_t flags = ntoh_u16(vhdr.flags);
    uint64_t pts = ntoh_u64(vhdr.pts);

    // Basic sanity checks
    if (total_packet_len == 0 || total_packet_len > MAX_UDP_REASSEMBLY_BYTES) {
        LOG_FEC_WARN("Dropping fragment: total_packet_len invalid (client {} seq {} len {})", client_id, packet_seq, total_packet_len);
        return;
    }
    if (frag_offset + frag_payload_len > total_packet_len) {
        LOG_FEC_WARN("Dropping fragment: out-of-bounds (client {} seq {} off {} len {} total {})",
                     client_id, packet_seq, frag_offset, frag_payload_len, total_packet_len);
        return;
    }
    if ((size_t)n < sizeof(vhdr) + frag_payload_len) {
        LOG_FEC_WARN("Fragment payload shorter than header says: recv {} expected {}", n, sizeof(vhdr) + frag_payload_len);
        return;
    }

    // Find connection by client ID
    Connection* conn = nullptr;
    for (auto &kv : clients_) {
        if (kv.second.clientId == client_id) {
            conn = &kv.second;
            // store udp addr if not set
            if (!conn->udp_addr_set) {
                conn->udp_addr = src;
                conn->udp_addr_set = true;
                LOG_NET_INFO("Stored UDP address for client {}: {}", client_id, inet_ntoa(src.sin_addr));
            }
            break;
        }
    }
    if (!conn) {
        LOG_NET_INFO("Video fragment from unknown client {} - ignoring", client_id);
        return;
    }

    // Reassembly key
    uint64_t key = make_inprogress_key(client_id, packet_seq);
    auto it = inprogress_map_.find(key);
    if (it == inprogress_map_.end()) {
        // Create new inprogress
        InProgress ip;
        ip.client_id = client_id;
        ip.packet_seq = packet_seq;
        ip.total_packet_len = total_packet_len;
        ip.total_frags = total_frags;
        ip.pts = pts;
        ip.buffer.assign(total_packet_len, 0);
        ip.fragment_received.assign(total_frags, 0);
        ip.received_bytes = 0;
        ip.first_seen = std::chrono::steady_clock::now();

        auto res = inprogress_map_.emplace(key, std::move(ip));
        it = res.first;
    }

    InProgress &ip = it->second;

    // bounds check frag_index
    if (frag_index >= ip.fragment_received.size()) {
        LOG_FEC_WARN("Bad frag_index {} for client {} seq {} total_frags {}", frag_index, client_id, packet_seq, ip.fragment_received.size());
        return;
    }

    // If this fragment already received (by index) we can skip copying but re-check partial overlap: we rely on per-frag granularity
    if (!ip.fragment_received[frag_index]) {
        // copy payload into buffer at frag_offset
        memcpy(ip.buffer.data() + frag_offset, buf + sizeof(vhdr), frag_payload_len);
        ip.fragment_received[frag_index] = 1;
        ip.received_bytes += frag_payload_len;
    } else {
        // duplicate fragment - ignore
    }

    LOG_FEC_DEBUG("Received fragment client={} seq={} frag={}/{} off={} len={} got_bytes={}/{}",
                  client_id, packet_seq, frag_index, total_frags, frag_offset, frag_payload_len, ip.received_bytes, ip.total_packet_len);

    // If we've received all bytes (simple test), assemble and decode
    if (ip.received_bytes >= ip.total_packet_len) {
        // Move assembled buffer into local vector and erase inprogress
        std::vector<char> assembled = std::move(ip.buffer);
        inprogress_map_.erase(it);

        // decode assembled packet with StubFec decoder (it expects FEC header + encoded payload)
        StubFec decoder;
        auto pkt = decoder.decode_packet(assembled.data(), assembled.size());
        if (pkt.payload.empty()) {
            LOG_FEC_ERROR("decode failed for client_id={} seq={}", client_id, packet_seq);
            return;
        }

        // pkt.payload is a vector<char> with one or more annex-b NALs
        bool payload_has_sps = false, payload_has_pps = false, payload_has_idr = false;
        analyze_nal_types(pkt.payload, payload_has_sps, payload_has_pps, payload_has_idr);

        if (payload_has_sps) {
            conn->sps_received = true;
            conn->sps_data = pkt.payload;
            LOG_PLAYER_INFO("Detected SPS for client_id={}", conn->clientId);
        }
        if (payload_has_pps) {
            conn->pps_received = true;
            conn->pps_data = pkt.payload;
            LOG_PLAYER_INFO("Detected PPS for client_id={}", conn->clientId);
        }

        // Create video frame with timestamp
        VideoFrame frame;
        frame.data = pkt.payload;
        frame.is_keyframe = payload_has_idr;
        frame.pts = pkt.pts;

        // Add to frame queue
        conn->frame_queue.push(frame);

        if (!conn->first_frame_received) {
            conn->first_frame_received = true;
            conn->first_pts = frame.pts;
            conn->playback_start = std::chrono::steady_clock::now();
            conn->playback_started = true;
        }

        LOG_PLAYER_INFO("Queued frame for client_id={} pts={} is_keyframe={} size={}",
                        conn->clientId, frame.pts, frame.is_keyframe, frame.data.size());
    }
}

void Server::processFrameQueue(Connection &conn) {
    // If playback hasn't been started for this connection, don't try to schedule.
    if (!conn.playback_started) return;

    while (!conn.frame_queue.empty()) {
        VideoFrame &frame = conn.frame_queue.front();

        // Compute elapsed wall clock (ms) since we started playback for this connection
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - conn.playback_start).count();

        // Compute target offset relative to first_pts
        int64_t target_offset = (int64_t)frame.pts - (int64_t)conn.first_pts; // ms
        if (target_offset < 0) target_offset = 0;

        // If it's time to display this frame (or queue too big)
        if ((int64_t)elapsed_ms >= target_offset || conn.frame_queue.size() > 10) {
            // For keyframes, make sure we have SPS/PPS
            if (frame.is_keyframe && conn.sps_received && conn.pps_received) {
                // Prepend SPS and PPS to keyframe
                std::vector<char> combined;
                combined.insert(combined.end(), conn.sps_data.begin(), conn.sps_data.end());
                combined.insert(combined.end(), conn.pps_data.begin(), conn.pps_data.end());
                combined.insert(combined.end(), frame.data.begin(), frame.data.end());

                ssize_t w = conn.player->write_data(combined.data(), combined.size());
                if (w < 0) {
                    conn.state = State::CLOSING;
                    return;
                }
                if ((size_t)w < combined.size()) {
                    conn.playerBuffer.append(combined.data() + w, combined.data() + combined.size());
                }

                LOG_PLAYER_INFO("Sent keyframe with SPS/PPS for client_id={} pts={} size={}",
                                conn.clientId, frame.pts, combined.size());
            } else {
                // Send frame as-is
                ssize_t w = conn.player->write_data(frame.data.data(), frame.data.size());
                if (w < 0) {
                    conn.state = State::CLOSING;
                    return;
                }
                if ((size_t)w < frame.data.size()) {
                    conn.playerBuffer.append(frame.data.data() + w, frame.data.data() + frame.data.size());
                }

                LOG_PLAYER_INFO("Sent frame for client_id={} pts={} size={}",
                                conn.clientId, frame.pts, frame.data.size());
            }

            // Log latency: difference between wallclock elapsed and target offset
            int64_t latency = (int64_t)elapsed_ms - target_offset;
            LOG_VIDEO_INFO("frame_latency: client_id={} pts={} target_offset={} elapsed={} latency={} queue_size={}",
                           conn.clientId, frame.pts, target_offset, (uint64_t)elapsed_ms, latency, (uint32_t)conn.frame_queue.size());

            conn.frame_queue.pop();
        } else {
            // Not yet time to display this frame
            break;
        }
    }

    // Check player buffer size
    if (conn.playerBuffer.size() > MAX_PLAYER_BUFFER_HARD) {
        LOG_GEN_ERROR("player_buf exceeded HARD limit for client {}; closing", conn.clientId);
        conn.state = State::CLOSING;
    } else if (conn.playerBuffer.size() > MAX_PLAYER_BUFFER) {
        size_t drop = conn.playerBuffer.size() / 2;
        conn.playerBuffer.erase(0, drop);
        LOG_GEN_WARN("player_buf exceeded soft limit for client {}; dropped {} bytes", conn.clientId, drop);
    }
}

void Server::flushPlayerBuffer(Connection &c) {
    if (c.playerBuffer.empty()) return;
    ssize_t w = c.player->write_data(c.playerBuffer.data(), c.playerBuffer.size());
    if (w < 0) {
        c.state = State::CLOSING;
    } else if ((size_t)w >= c.playerBuffer.size()) {
        LOG_PLAYER_INFO("Flushed playerBuffer client_id={} bytes={}", c.clientId, (uint32_t)w);
        c.playerBuffer.clear();
    } else {
        c.playerBuffer.erase(0, (size_t)w);
        LOG_PLAYER_INFO("Partial flush, wrote={} remain={}", (uint32_t)w, (uint32_t)c.playerBuffer.size());
    }
}

void Server::handlePlayerFdEvent(int playerFd) {
#ifdef __linux__
    auto pit = playerFdToClientFd_.find(playerFd);
    if (pit == playerFdToClientFd_.end()) return;
    sock_t clientFd = pit->second;
    auto cit = clients_.find(clientFd);
    if (cit == clients_.end()) return;
    flushPlayerBuffer(cit->second);
#endif
}

void Server::closeConnection(sock_t fd) {
    auto it = clients_.find(fd);
    if (it == clients_.end()) return;
    Connection &conn = it->second;
#ifdef __linux__
    int pfd = conn.player ? conn.player->get_write_fd() : -1;
    if (pfd >= 0) {
        epoll_ctl(epollFd_, EPOLL_CTL_DEL, pfd, nullptr);
        playerFdToClientFd_.erase(pfd);
    }
    epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
#endif
    if (conn.player) {
        conn.player->stop();
        LOG_PLAYER_INFO("Stopped player for client_id={} fd={}", conn.clientId, (long long)fd);
    }
    closeSocket(fd);
    clients_.erase(it);
    LOG_GEN_INFO("Closed connection fd={}", (long long)fd);
}
