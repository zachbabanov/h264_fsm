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
#include <fstream>
#include <algorithm>

using namespace project::client;
using namespace project::log;

static void print_usage(const char *prog) {
    std::cerr << "Usage: " << prog << " [--bitrate <kbps>] [--no-fec] [--log <log_file>] [--log-level debug|info|warn|error] <host:port> <h264_file> <loop (0|1)>\n";
    std::cerr << "Example: " << prog << " --bitrate 1000 --log client.log --log-level info 127.0.0.1:8000 test.h264 1\n";
    std::cerr << "Example (no FEC): " << prog << " --no-fec --log client.log 127.0.0.1:8000 test.h264 0\n";
}

static Level parse_log_level_or_default(const std::string &s, Level def = Level::INFO) {
    std::string v = s;
    std::transform(v.begin(), v.end(), v.begin(), ::tolower);
    if (v == "debug") return Level::DEBUG;
    if (v == "info") return Level::INFO;
    if (v == "warn" || v == "warning") return Level::WARN;
    if (v == "error" || v == "err") return Level::ERROR;
    // unknown
    std::cerr << "Warning: unknown log level '" << s << "', using default.\n";
    return def;
}

int main(int argc, char **argv) {
    // Default level will be set after parsing CLI
    Level desired_level = Level::INFO;

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
    std::string log_level_str;

    // Simple arg parsing that allows --bitrate, --no-fec, --log, --log-level anywhere
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
        } else if (a == "--log-level") {
            if (i + 1 >= argc) {
                std::cerr << "--log-level requires a value (debug|info|warn|error)\n";
                return 1;
            }
            log_level_str = argv[i+1];
            i++;
        } else {
            pos.push_back(a);
        }
    }

    // Validate positional args
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
        try {
            port = std::stoi(port_s);
        } catch (...) {
            std::cerr << "Invalid port: " << port_s << "\n";
            return 1;
        }
    }

    // parse & set log level
    if (!log_level_str.empty()) {
        desired_level = parse_log_level_or_default(log_level_str, Level::INFO);
    }
    Logger::instance().set_level(desired_level);

    // If user provided a log file, test opening it first for append/writability
    if (!log_file.empty()) {
        std::ofstream ofs(log_file.c_str(), std::ios::app);
        if (!ofs) {
            std::cerr << "Warning: could not open log file '" << log_file << "' for append — continuing without file logging\n";
        } else {
            ofs.close();
            // Assuming Logger::open_logfile accepts const char*
            Logger::instance().open_logfile(log_file.c_str());
        }
    }

    LOG_GEN_INFO("Starting client -> {}:{} file='{}' loop={} initial_bitrate_kbps={} use_fec={}",
                 host, port, h264file, loop ? 1 : 0, initial_bitrate_kbps, use_fec ? "yes" : "no");

    // Client constructor overload that accepts use_fec flag
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
