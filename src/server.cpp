#include "server.hpp"
#include "common.hpp"
#include "encoder.hpp" // StubFec, FecPacketHeader, project::fec::FEC_PACKET_HEADER_SIZE
#include "logger.hpp"
#include <cerrno>
#include <cstring>
#include <iostream>
#include <algorithm>

#ifdef __linux__
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
  #endif
#endif

using namespace project::server;
using namespace project::common;
using namespace project::fec;
using namespace project::log;

/**
 * analyze_nal_types:
 *  Scans Annex-B formatted payload (may contain 1+ NALs) and sets flags
 *  hasSps/hasPps when finds nal_unit_type == 7/8 respectively.
 */
void Server::analyze_nal_types(const std::vector<char> &payload, bool &hasSps, bool &hasPps) {
    hasSps = hasSps || false;
    hasPps = hasPps || false;
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
        // move p to search next start code after nal_header
        p = nal_header + 1;
    }
}

Server::Server(int tcpPort, const std::string &playerCmd)
        : tcpPort_(tcpPort),
          udpPort_(tcpPort + 1),
          listenSocket_(INVALID_SOCK),
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
    if (listenSocket_ != INVALID_SOCK) closeSocket(listenSocket_);
#ifdef _WIN32
    WSACleanup();
#endif
}

bool Server::setupListenSocket() {
    listenSocket_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket_ == INVALID_SOCK) {
        LOG_GEN_ERROR("Failed to create listen socket");
        return false;
    }

    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(tcpPort_);

    if (bind(listenSocket_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_GEN_ERROR("bind failed on port {}", tcpPort_);
        closeSocket(listenSocket_);
        return false;
    }

    if (setSocketNonBlocking(listenSocket_) < 0) {
        LOG_GEN_ERROR("set nonblocking failed for listen socket");
        closeSocket(listenSocket_);
        return false;
    }

    if (listen(listenSocket_, 64) < 0) {
        LOG_GEN_ERROR("listen failed");
        closeSocket(listenSocket_);
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
    ev.data.fd = listenSocket_;
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, listenSocket_, &ev) < 0) {
        perror("epoll_ctl add listen");
        return false;
    }

    // UDP for control
    sock_t udpFd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udpFd == INVALID_SOCK) { perror("udp socket"); return false; }
    sockaddr_in uaddr{};
    uaddr.sin_family = AF_INET;
    uaddr.sin_addr.s_addr = INADDR_ANY;
    uaddr.sin_port = htons(udpPort_);
    if (bind(udpFd, (sockaddr*)&uaddr, sizeof(uaddr)) < 0) { perror("udp bind"); closeSocket(udpFd); return false; }
    setSocketNonBlocking(udpFd);
    ev.events = EPOLLIN;
    ev.data.fd = udpFd;
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, udpFd, &ev) < 0) { perror("epoll_ctl add udp"); closeSocket(udpFd); return false; }
    LOG_GEN_INFO("UDP listening on port {}", udpPort_);
#else
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
            if (fd == listenSocket_) {
                acceptNewConnections();
            } else {
                // check if this is a player write-fd
                auto pit = playerFdToClientFd_.find(fd);
                if (pit != playerFdToClientFd_.end()) {
                    handlePlayerFdEvent(fd);
                } else {
                    if (clients_.count(fd)) {
                        handleClientEvent(fd, ev);
                    } else {
                        handleUdpPacket(fd);
                    }
                }
            }
        }
    }
#else
    // Windows WSAPoll loop (not fully changed here)
    sock_t udpFd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udpFd == INVALID_SOCKET) {
        LOG_GEN_ERROR("Failed to create UDP socket");
        return;
    }
    sockaddr_in uaddr{};
    uaddr.sin_family = AF_INET;
    uaddr.sin_addr.s_addr = INADDR_ANY;
    uaddr.sin_port = htons(udpPort_);
    if (bind(udpFd, (sockaddr*)&uaddr, sizeof(uaddr)) == SOCKET_ERROR) {
        LOG_GEN_ERROR("UDP bind failed");
        closeSocket(udpFd);
        return;
    }
    setSocketNonBlocking(udpFd);

    while (true) {
        std::vector<WSAPOLLFD> fds;
        WSAPOLLFD lfd{};
        lfd.fd = listenSocket_;
        lfd.events = POLLIN;
        fds.push_back(lfd);

        WSAPOLLFD ufd{};
        ufd.fd = udpFd;
        ufd.events = POLLIN;
        fds.push_back(ufd);

        for (auto &kv : clients_) {
            WSAPOLLFD cfd{};
            cfd.fd = kv.first;
            cfd.events = POLLIN;
            fds.push_back(cfd);
        }

        int ret = WSAPoll(fds.data(), (ULONG)fds.size(), 1000);
        if (ret == SOCKET_ERROR) {
            LOG_GEN_ERROR("WSAPoll failed");
            break;
        }
        if (ret == 0) continue;

        if (fds[0].revents & POLLIN) acceptNewConnections();
        if (fds[1].revents & POLLIN) handleUdpPacket(udpFd);

        for (size_t i = 2; i < fds.size(); ++i) {
            sock_t fd = fds[i].fd;
            uint32_t re = fds[i].revents;
            if (clients_.count(fd)) handleClientEvent(fd, re);
        }
    }
    closeSocket(udpFd);
#endif
}

void Server::acceptNewConnections() {
    while (clients_.size() < MAX_CLIENTS) {
        sockaddr_in caddr{};
        socklen_t clen = sizeof(caddr);
        sock_t cfd = accept(listenSocket_, (sockaddr*)&caddr, &clen);
        if (cfd == INVALID_SOCK) {
#ifdef __linux__
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("accept");
#else
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

            // Launch player process (PlayerProcess defined in player.hpp)
            conn.player = project::player::PlayerProcess::launch(playerCmd_);
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

void Server::handleClientEvent(sock_t fd, uint32_t events) {
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
                        // parse complete FEC packets using encoder's header size
                        while (conn.inBuffer.size() >= project::fec::FEC_PACKET_HEADER_SIZE) {
                            FecPacketHeader hdr = StubFec::parse_header(conn.inBuffer.data(), project::fec::FEC_PACKET_HEADER_SIZE);
                            size_t payload_len = hdr.payload_len;
                            size_t total_needed = project::fec::FEC_PACKET_HEADER_SIZE + payload_len;
                            if (conn.inBuffer.size() < total_needed) break;
                            std::vector<char> packet(conn.inBuffer.begin(), conn.inBuffer.begin() + total_needed);
                            conn.inBuffer.erase(0, total_needed);

                            // decode with FEC stub (should return payload bytes that are Annex-B NALs)
                            StubFec decoder;
                            auto pkt = decoder.decode_packet(packet.data(), packet.size());
                            if (pkt.payload.empty() && payload_len > 0) {
                                LOG_FEC_ERROR("decode failed for client_id={} seq={}", hdr.client_id, hdr.packet_seq);
                                conn.state = State::CLOSING;
                                break;
                            }

                            // pkt.payload is a vector<char> with one or more annex-b NALs
                            bool payload_has_sps = false, payload_has_pps = false;
                            analyze_nal_types(pkt.payload, payload_has_sps, payload_has_pps);

                            if (!conn.sps_received || !conn.pps_received) {
                                // Buffer until we have both SPS and PPS
                                if (payload_has_sps && !conn.sps_received) {
                                    conn.sps_received = true;
                                    conn.sps_data = pkt.payload; // store entire payload (may contain SPS + maybe others)
                                    LOG_PLAYER_INFO("Detected SPS for client_id={}", conn.clientId);
                                }
                                if (payload_has_pps && !conn.pps_received) {
                                    conn.pps_received = true;
                                    conn.pps_data = pkt.payload;
                                    LOG_PLAYER_INFO("Detected PPS for client_id={}", conn.clientId);
                                }
                                // push raw payload into buffered packets
                                conn.buffered_packets.emplace_back(pkt.payload);
                                // if now both found, flush: put SPS and PPS first, then all buffered packets (skipping duplicates)
                                if (conn.sps_received && conn.pps_received) {
                                    // Build a combined buffer: first unique SPS, then PPS, then remaining packets without duplicating SPS/PPS
                                    std::string combined;
                                    // helper lambda to append vector<char> to combined string
                                    auto append_vec = [&](const std::vector<char> &v) {
                                        combined.append(v.data(), v.data() + v.size());
                                    };

                                    // Ensure we append actual SPS and PPS NALs themselves:
                                    // We attempt to extract SPS and PPS NALs from stored sps_data/pps_data;
                                    // if sps_data/pps_data are larger than single NAL, that's ok — we append as-is.
                                    append_vec(conn.sps_data);
                                    append_vec(conn.pps_data);

                                    // then append buffered packets in original order, skipping those equal to sps/pps to avoid duplicates
                                    for (const auto &b : conn.buffered_packets) {
                                        if (b == conn.sps_data || b == conn.pps_data) continue;
                                        append_vec(b);
                                    }

                                    // Now write combined to player (using write_data)
                                    ssize_t w = conn.player->write_data(combined.data(), combined.size());
                                    if (w < 0) {
                                        conn.state = State::CLOSING;
                                        break;
                                    }
                                    if ((size_t)w < combined.size()) {
                                        conn.playerBuffer.append(combined.data() + w, combined.data() + combined.size());
                                    }
                                    conn.buffered_packets.clear();
                                    LOG_PLAYER_INFO("Flushed buffered stream to player for client_id={} bytes={}", conn.clientId, (uint32_t)combined.size());
                                } else {
                                    // Not enough info yet — continue buffering
                                    LOG_PLAYER_INFO("Buffered packet for client_id={} buffered_count={} (sps={}, pps={})", conn.clientId, (unsigned)conn.buffered_packets.size(), conn.sps_received, conn.pps_received);
                                    // Enforce buffer limits
                                    size_t total_buf_bytes = 0;
                                    for (const auto &bp : conn.buffered_packets) total_buf_bytes += bp.size();
                                    if (total_buf_bytes > MAX_PLAYER_BUFFER_HARD) {
                                        LOG_GEN_ERROR("buffered_packets exceeded HARD limit for client {}; closing", conn.clientId);
                                        conn.state = State::CLOSING;
                                        break;
                                    } else if (total_buf_bytes > MAX_PLAYER_BUFFER) {
                                        // drop first half of buffered packets
                                        size_t drop_cnt = conn.buffered_packets.size() / 2;
                                        conn.buffered_packets.erase(conn.buffered_packets.begin(), conn.buffered_packets.begin() + drop_cnt);
                                        LOG_GEN_WARN("Dropped {} buffered packets for client_id={} due soft buffer limit", (unsigned)drop_cnt, conn.clientId);
                                    }
                                }
                            } else {
                                // we already have SPS/PPS — write directly to player (respecting partial writes)
                                ssize_t w = conn.player->write_data(pkt.payload.data(), pkt.payload.size());
                                if (w < 0) {
                                    conn.state = State::CLOSING;
                                    break;
                                }
                                if ((size_t)w < pkt.payload.size()) {
                                    conn.playerBuffer.append(pkt.payload.data() + w, pkt.payload.data() + pkt.payload.size());
                                    if (conn.playerBuffer.size() > MAX_PLAYER_BUFFER_HARD) {
                                        LOG_GEN_ERROR("player_buf exceeded HARD limit for client {}; closing", conn.clientId);
                                        conn.state = State::CLOSING;
                                        break;
                                    } else if (conn.playerBuffer.size() > MAX_PLAYER_BUFFER) {
                                        size_t drop = conn.playerBuffer.size() / 2;
                                        conn.playerBuffer.erase(0, drop);
                                        LOG_GEN_WARN("player_buf exceeded soft limit for client {}; dropped {} bytes", conn.clientId, drop);
                                    }
#ifdef __linux__
                                    int pfd = conn.player->get_write_fd();
                                    if (pfd >= 0) {
                                        epoll_event ev{};
                                        ev.events = EPOLLOUT | EPOLLET;
                                        ev.data.fd = pfd;
                                        epoll_ctl(epollFd_, EPOLL_CTL_MOD, pfd, &ev);
                                    }
#endif
                                }
                            }
                        } // parsing loop
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
            // handled by player fd events
            break;
        case State::CLOSING:
            closeConnection(fd);
            break;
        default:
            break;
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

void Server::handleUdpPacket(sock_t udpFd) {
    char buf[1500];
    sockaddr_in src{};
    socklen_t sl = sizeof(src);
    int n = recvfrom(udpFd, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
    if (n <= 0) return;
    if ((size_t)n < sizeof(UdpHeader)) {
        LOG_NET_INFO("short udp packet from {}", inet_ntoa(src.sin_addr));
        return;
    }
    UdpHeader hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    uint32_t client_id = ntoh_u32(hdr.client_id);
    uint16_t cmd = ntoh_u16(hdr.command_id);
    uint32_t seq = ntoh_u32(hdr.seq);
    std::string payload;
    if ((size_t)n > sizeof(hdr)) payload.assign(buf + sizeof(hdr), buf + n);

    switch (cmd) {
        case CMD_REGISTER: {
            uint32_t assigned = client_id ? client_id : nextClientId_++;
            LOG_NET_INFO("UDP REGISTER from {} seq={} -> assign {}", inet_ntoa(src.sin_addr), seq, assigned);
            UdpHeader resp{};
            resp.client_id = hton_u32(assigned);
            resp.command_id = hton_u16(CMD_REGISTER_RESP);
            resp.flags = 0;
            resp.seq = hton_u32(seq);
            sendto(udpFd, (char*)&resp, (int)sizeof(resp), 0, (sockaddr*)&src, sl);
            break;
        }
        case CMD_HEARTBEAT:
            LOG_NET_INFO("UDP HEARTBEAT id={} seq={}", client_id, seq);
            break;
        case CMD_BROADCAST:
            LOG_NET_INFO("UDP BROADCAST id={} len={}", client_id, payload.size());
            for (auto &kv : clients_) {
                Connection &cc = kv.second;
                cc.playerBuffer.append(payload);
                if (cc.playerBuffer.size() > MAX_PLAYER_BUFFER_HARD) {
                    cc.state = State::CLOSING;
                } else if (cc.playerBuffer.size() > MAX_PLAYER_BUFFER) {
                    size_t drop = cc.playerBuffer.size() / 2;
                    cc.playerBuffer.erase(0, drop);
                }
#ifdef __linux__
                int pfd = cc.player ? cc.player->get_write_fd() : -1;
                if (pfd >= 0) {
                    epoll_event ev{};
                    ev.events = EPOLLOUT | EPOLLET;
                    ev.data.fd = pfd;
                    epoll_ctl(epollFd_, EPOLL_CTL_MOD, pfd, &ev);
                    playerFdToClientFd_[pfd] = kv.first;
                }
#endif
            }
            break;
        default:
            LOG_GEN_WARN("Unknown UDP cmd {}", cmd);
            break;
    }
}
