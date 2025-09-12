/*
* @license
* (C) zachbabanov
*
*/

#ifndef PROJECT_COMMON_HPP
#define PROJECT_COMMON_HPP

#pragma once

#include <cstdint>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#define INVALID_SOCK INVALID_SOCKET
#else
#define INVALID_SOCK (-1)
#endif

namespace project {
    namespace common {
#ifdef _WIN32
        using sock_t = SOCKET;
#else
        using sock_t = int;
#endif

// Constants used across server/client
        constexpr size_t BUFFER_SIZE = 4096;
        constexpr size_t MAX_CLIENTS = 16;
        constexpr size_t MAX_PLAYER_BUFFER = 4 * 1024 * 1024;       // 4 MB soft
        constexpr size_t MAX_PLAYER_BUFFER_HARD = 16 * 1024 * 1024; // 16 MB hard
        constexpr size_t MAX_UDP_PACKET_SIZE = 1400;                // MTU-friendly size for video packets
        constexpr size_t MAX_UDP_REASSEMBLY_BYTES = 16 * 1024 * 1024; // 16 MiB max reassembly

//
// UDP / control protocol commands
//
        constexpr uint16_t CMD_REGISTER = 1;
        constexpr uint16_t CMD_REGISTER_RESP = 2;
        constexpr uint16_t CMD_HEARTBEAT = 3;
        constexpr uint16_t CMD_BROADCAST = 4;
        constexpr uint16_t CMD_SET_BITRATE = 5; // command over TCP
        constexpr uint16_t CMD_VIDEO_DATA = 6;  // marker for video fragments (UDP)

        // Control header used for TCP control messages (also reused in some places)
#pragma pack(push,1)
        struct UdpHeader {
            uint32_t client_id;
            uint16_t command_id;
            uint16_t flags;
            uint32_t seq;
        };
#pragma pack(pop)

        // UDP video fragment header (packed). Sent BEFORE fragment payload bytes.
        // Fixed size = 32 bytes.
#pragma pack(push,1)
        struct UdpVideoFragmentHeader {
            uint32_t client_id;          // 0..3
            uint32_t packet_seq;         // 4..7
            uint32_t total_packet_len;   // 8..11 total length of the whole encoded packet (header+payload)
            uint32_t frag_offset;        // 12..15 offset into total packet where this fragment belongs
            uint16_t frag_payload_len;   // 16..17 length of payload bytes in this fragment
            uint16_t total_frags;        // 18..19 total number of fragments (informational)
            uint16_t frag_index;         // 20..21 fragment index (0-based)
            uint16_t flags;              // 22..23 reserved flags (e.g., PROBE)
            uint64_t pts;                // 24..31 PTS in milliseconds (client-supplied)
        };
#pragma pack(pop)

//
// Utility functions
//
        int setSocketNonBlocking(sock_t fd);
        void closeSocket(sock_t fd);
        int enableSocketKeepAliveAndNoDelay(sock_t fd);

        uint64_t ntoh_u64(uint64_t v);
        uint64_t hton_u64(uint64_t v);
        uint32_t ntoh_u32(uint32_t v);
        uint16_t ntoh_u16(uint16_t v);
        uint32_t hton_u32(uint32_t v);
        uint16_t hton_u16(uint16_t v);

    } // namespace common
} // namespace project

#endif // PROJECT_COMMON_HPP
