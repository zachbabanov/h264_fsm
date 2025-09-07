#include "common.hpp"
#include "logger.hpp"
#include <cerrno>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#endif

namespace project {
    namespace common {

        using namespace project::log;

        int setSocketNonBlocking(sock_t fd) {
#ifdef _WIN32
            u_long mode = 1;
    if (ioctlsocket(fd, FIONBIO, &mode) != 0) {
        LOG_NET_INFO("setSocketNonBlocking failed: socket={} err={}", (long long)fd, WSAGetLastError());
        return -1;
    }
    return 0;
#else
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags == -1) {
                LOG_NET_INFO("fcntl F_GETFL failed: fd={} err={}", fd, strerror(errno));
                return -1;
            }
            if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
                LOG_NET_INFO("fcntl F_SETFL failed: fd={} err={}", fd, strerror(errno));
                return -1;
            }
            return 0;
#endif
        }

        void closeSocket(sock_t fd) {
#ifdef _WIN32
            if (fd != INVALID_SOCKET) {
        closesocket(fd);
        LOG_NET_INFO("socket closed: {}", (long long)fd);
    }
#else
            if (fd >= 0) {
                close(fd);
                LOG_NET_INFO("socket closed: {}", fd);
            }
#endif
        }

        int enableSocketKeepAliveAndNoDelay(sock_t fd) {
#ifdef _WIN32
            BOOL opt = TRUE;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        LOG_NET_INFO("setsockopt(SO_KEEPALIVE) failed socket={} err={}", (long long)fd, WSAGetLastError());
    }
    opt = TRUE;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        LOG_NET_INFO("setsockopt(TCP_NODELAY) failed socket={} err={}", (long long)fd, WSAGetLastError());
    }
    return 0;
#else
            int on = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) != 0) {
                LOG_NET_INFO("setsockopt(SO_KEEPALIVE) failed fd={} err={}", fd, strerror(errno));
            }
            // platform-specific keepalive tuning (best-effort)
#ifdef TCP_KEEPIDLE
            int idle = 30;
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
            int interval = 5;
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
#endif
#ifdef TCP_KEEPCNT
            int cnt = 3;
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif

            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) != 0) {
                LOG_NET_INFO("setsockopt(TCP_NODELAY) failed fd={} err={}", fd, strerror(errno));
            }
            return 0;
#endif
        }

        uint32_t ntoh_u32(uint32_t v) { return ntohl(v); }
        uint16_t ntoh_u16(uint16_t v) { return ntohs(v); }
        uint32_t hton_u32(uint32_t v) { return htonl(v); }
        uint16_t hton_u16(uint16_t v) { return htons(v); }

    } // namespace common
} // namespace project
