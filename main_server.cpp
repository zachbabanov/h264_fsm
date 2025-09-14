/*
* @license
* (C) zachbabanov
*
*/

#include <server.hpp>
#include <logger.hpp>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

using namespace project::log;

static void print_usage(const char *prog) {
    std::cerr << "Usage: " << prog << " [--log <log_file>] [--log-level debug|info|warn|error] <tcp_port> [ffplay_path]\n";
    std::cerr << "Example: " << prog << " --log server.log --log-level info 8000 ffplay\n";
}

static Level parse_log_level_or_default(const std::string &s, Level def = Level::INFO) {
    std::string v = s;
    std::transform(v.begin(), v.end(), v.begin(), ::tolower);
    if (v == "debug") return Level::DEBUG;
    if (v == "info") return Level::INFO;
    if (v == "warn" || v == "warning") return Level::WARN;
    if (v == "error" || v == "err") return Level::ERROR;
    std::cerr << "Warning: unknown log level '" << s << "', using default.\n";
    return def;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string log_file;
    std::string log_level_str;
    std::vector<std::string> pos;

    // parse flags --log and --log-level, rest are positional
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a == "--log") {
            if (i + 1 >= argc) {
                std::cerr << "--log requires a path\n";
                return 1;
            }
            log_file = argv[i+1];
            i++;
        } else if (a == "--log-level") {
            if (i + 1 >= argc) {
                std::cerr << "--log-level requires a value\n";
                return 1;
            }
            log_level_str = argv[i+1];
            i++;
        } else {
            pos.push_back(a);
        }
    }

    if (pos.size() < 1) {
        print_usage(argv[0]);
        return 1;
    }

    // positional: <tcp_port> [ffplay_path]
    int port = 0;
    try {
        port = std::stoi(pos[0]);
    } catch (...) {
        std::cerr << "Invalid port: " << pos[0] << "\n";
        return 1;
    }
    std::string player = (pos.size() >= 2) ? pos[1] : std::string("ffplay");

    // parse & set log level
    Level desired_level = Level::INFO;
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
            Logger::instance().open_logfile(log_file.c_str());
        }
    }

    project::server::Server srv(port, player);
    if (!srv.start()) {
        LOG_GEN_ERROR("Server failed to start");
        return 1;
    }
    srv.runLoop();
    return 0;
}
