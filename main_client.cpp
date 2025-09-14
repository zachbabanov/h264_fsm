/*
* @license
* (C) zachbabanov
*
*/

#include <client.hpp>
#include <logger.hpp>

#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>

using namespace project::client;
using namespace project::log;

static void print_usage(const char *prog) {
    std::cerr << "Usage: " << prog << " [--bitrate <kbps>] [--no-fec] [--log <log_file>] <host:port> <h264_file> <loop (0|1)>\n";
    std::cerr << "Example: " << prog << " --bitrate 1000 --log client.log 127.0.0.1:8000 test.h264 1\n";
    std::cerr << "Example (no FEC): " << prog << " --no-fec 127.0.0.1:8000 test.h264 0\n";
}

int main(int argc, char **argv) {
    // default level; caller can override by editing code or adding a CLI flag in the future
    Logger::instance().set_level(Level::DEBUG);

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    std::string hostport;
    std::string h264file;
    bool loop = false;
    uint32_t initial_bitrate_kbps = 0;
    bool use_fec = true;
    std::string log_file;

    // Simple arg parsing that allows --bitrate, --no-fec and --log anywhere
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a == "--bitrate") {
            if (i + 1 >= argc) {
                std::cerr << "--bitrate requires a value\n";
                return 1;
            }
            initial_bitrate_kbps = (uint32_t)std::stoul(argv[i+1]);
            i++;
        } else if (a == "--no-fec") {
            use_fec = false;
        } else if (a == "--log") {
            if (i + 1 >= argc) {
                std::cerr << "--log requires a path\n";
                return 1;
            }
            log_file = argv[i+1];
            i++;
        } else {
            pos.push_back(a);
        }
    }

    // If user provided a log file, open it
    if (!log_file.empty()) {
        // Logger::open_logfile likely accepts const char* or std::string; use c_str() for safety
        Logger::instance().open_logfile(log_file.c_str());
    }

    if (pos.size() < 3) {
        print_usage(argv[0]);
        return 1;
    }

    hostport = pos[0];
    h264file = pos[1];
    loop = (pos[2] != "0");

    // parse host:port
    std::string host;
    int port = 8000;
    size_t colon = hostport.find(':');
    if (colon == std::string::npos) {
        std::cerr << "host:port required\n";
        print_usage(argv[0]);
        return 1;
    } else {
        host = hostport.substr(0, colon);
        std::string port_s = hostport.substr(colon+1);
        port = std::stoi(port_s);
    }

    LOG_GEN_INFO("Starting client -> {}:{} file='{}' loop={} initial_bitrate_kbps={} use_fec={}",
                 host, port, h264file, loop ? 1 : 0, initial_bitrate_kbps, use_fec ? "yes" : "no");

    // New constructor overload includes use_fec flag
    Client c(host, port, h264file, loop, use_fec);
    if (initial_bitrate_kbps > 0) {
        c.set_initial_bitrate(initial_bitrate_kbps);
    }

    if (!c.run()) {
        LOG_GEN_ERROR("Client run failed");
        return 2;
    }
    return 0;
}
