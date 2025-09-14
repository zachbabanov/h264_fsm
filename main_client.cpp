/*
* @license
* (C) zachbabanov
*
*/

#include <client.hpp>
#include <logger.hpp>

#include <algorithm>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <sys/stat.h>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <limits.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

using json = nlohmann::json;

using namespace project::client;
using namespace project::log;

static bool file_exists(const std::string &path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

static std::string get_exe_dir(const char *argv0) {
    // Try platform-specific reliable method, otherwise fallback to dirname(argv0) or "."
#if defined(__linux__)
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len > 0) {
        buf[len] = '\0';
        std::string p(buf);
        size_t pos = p.find_last_of('/');
        if (pos != std::string::npos) return p.substr(0, pos);
    }
#elif defined(__APPLE__)
    // On macOS try _NSGetExecutablePath if available
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        std::string p(buf);
        size_t pos = p.find_last_of('/');
        if (pos != std::string::npos) return p.substr(0, pos);
    }
#elif defined(_WIN32)
    char buf[MAX_PATH];
    DWORD r = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (r > 0 && r < MAX_PATH) {
        std::string p(buf);
        size_t pos = p.find_last_of("\\/");
        if (pos != std::string::npos) return p.substr(0, pos);
    }
#endif

    // fallback: use argv0 path if it contains directory separator
    if (argv0) {
        std::string p(argv0);
        size_t pos = p.find_last_of("\\/");
        if (pos != std::string::npos) return p.substr(0, pos);
    }
    return "."; // otherwise current directory
}

static void print_usage(const char *prog) {
    std::cerr << "Usage: " << prog << " [--bitrate <kbps>] [--no-fec] [--stream <source>] [--log <log_file>] [--log-level debug|info|warn|error] <host:port> <h264_file_or_stream> <loop (0|1)>\n";
    std::cerr << "If no CLI options are provided, program will read config.json located next to the binary and use those settings.\n";
    std::cerr << "CLI options override values from config.json.\n";
    std::cerr << "Example: " << prog << " --bitrate 1000 --log client.log --log-level info 127.0.0.1:8000 test.h264 1\n";
    std::cerr << "Example (stream): " << prog << " --stream rtsp://example.com/stream --no-fec 127.0.0.1:8000 ignored 0\n";
}

// map log level string to enum
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

int main(int argc, char **argv) {
    // Defaults
    Level desired_level = Level::INFO;

    // CLI-collected values
    std::string hostport_cli;        bool hostport_cli_set = false;
    std::string h264_cli;            bool h264_cli_set = false;
    bool loop_cli = false;           bool loop_cli_set = false;
    uint32_t bitrate_cli = 0;        bool bitrate_cli_set = false;
    bool nofec_cli = false;          bool nofec_cli_set = false;
    std::string log_file_cli;        bool log_file_cli_set = false;
    std::string log_level_cli;       bool log_level_cli_set = false;
    bool stream_mode_cli = false;    bool stream_mode_cli_set = false;
    std::string stream_source_cli;   bool stream_source_cli_set = false;

    // Collect positional args separately
    std::vector<std::string> pos;

    // If there are CLI args beyond program name, parse them (note: --config removed per spec)
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a == "--bitrate") {
            if (i + 1 >= argc) { std::cerr << "--bitrate requires a value\n"; return 1; }
            bitrate_cli = (uint32_t)std::stoul(argv[++i]);
            bitrate_cli_set = true;
        } else if (a == "--no-fec") {
            nofec_cli = true;
            nofec_cli_set = true;
        } else if (a == "--stream") {
            if (i + 1 >= argc) { std::cerr << "--stream requires a source (e.g. rtsp://...)\n"; return 1; }
            stream_mode_cli = true;
            stream_mode_cli_set = true;
            stream_source_cli = argv[++i];
            stream_source_cli_set = true;
        } else if (a == "--log") {
            if (i + 1 >= argc) { std::cerr << "--log requires a path\n"; return 1; }
            log_file_cli = argv[++i];
            log_file_cli_set = true;
        } else if (a == "--log-level") {
            if (i + 1 >= argc) { std::cerr << "--log-level requires a value\n"; return 1; }
            log_level_cli = argv[++i];
            log_level_cli_set = true;
        } else if (a == "--help" || a == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            pos.push_back(a);
        }
    }

    // Determine whether any CLI options / positional provided
    bool any_cli = bitrate_cli_set || nofec_cli_set || log_file_cli_set || log_level_cli_set || stream_mode_cli_set || stream_source_cli_set || (!pos.empty());

    // Compute config.json path next to binary
    std::string exe_dir = get_exe_dir(argv && argc>0 ? argv[0] : nullptr);
    std::string default_config_path = exe_dir + "/config.json";
    bool config_loaded = false;

    // Config values (defaults)
    std::string host_cfg;
    std::string h264_cfg;
    bool loop_cfg = false;
    uint32_t bitrate_cfg = 0;
    bool use_fec_cfg = true;
    std::string log_file_cfg;
    std::string log_level_cfg;
    bool stream_mode_cfg = false;
    std::string stream_source_cfg;

    // If no CLI args provided at all -> require config.json
    if (!any_cli) {
        if (!file_exists(default_config_path)) {
            std::cerr << "No CLI arguments provided: expecting config.json next to the binary at: " << default_config_path << "\n";
            return 1;
        }
    }

    // If config exists, load it (even when CLI provided — used as defaults)
    if (file_exists(default_config_path)) {
        try {
            std::ifstream ifs(default_config_path);
            if (!ifs) {
                std::cerr << "Warning: cannot open config file '" << default_config_path << "' — ignoring\n";
            } else {
                json j;
                ifs >> j;
                // Fill config values if present
                if (j.contains("host")) {
                    std::string host = j["host"].get<std::string>();
                    int port = 8000;
                    if (j.contains("port")) port = j["port"].get<int>();
                    host_cfg = host + ":" + std::to_string(port);
                } else if (j.contains("hostport")) {
                    host_cfg = j["hostport"].get<std::string>();
                }
                if (j.contains("h264_file")) h264_cfg = j["h264_file"].get<std::string>();
                if (j.contains("loop")) loop_cfg = j["loop"].get<bool>();
                if (j.contains("bitrate_kbps")) bitrate_cfg = j["bitrate_kbps"].get<uint32_t>();
                if (j.contains("use_fec")) use_fec_cfg = j["use_fec"].get<bool>();
                if (j.contains("log_file")) log_file_cfg = j["log_file"].get<std::string>();
                if (j.contains("log_level")) log_level_cfg = j["log_level"].get<std::string>();
                if (j.contains("stream_mode")) stream_mode_cfg = j["stream_mode"].get<bool>();
                if (j.contains("stream_source")) stream_source_cfg = j["stream_source"].get<std::string>();

                // backwards compat: allow "stream" object with source and enabled
                if (j.contains("stream") && j["stream"].is_object()) {
                    auto s = j["stream"];
                    if (s.contains("source")) stream_source_cfg = s["source"].get<std::string>();
                    if (s.contains("enabled")) stream_mode_cfg = s["enabled"].get<bool>();
                }
                config_loaded = true;
                LOG_GEN_INFO("Loaded client config from '{}'", default_config_path);
            }
        } catch (std::exception &e) {
            std::cerr << "Warning: error parsing config '" << default_config_path << "': " << e.what() << " — ignoring\n";
        }
    }

    // Determine final values: start from config values, then override with CLI
    std::string hostport_final = host_cfg;
    std::string h264_final = h264_cfg;
    bool loop_final = loop_cfg;
    uint32_t bitrate_final = bitrate_cfg;
    bool use_fec_final = use_fec_cfg;
    std::string log_file_final = log_file_cfg;
    std::string log_level_final = log_level_cfg;
    bool stream_mode_final = stream_mode_cfg;
    std::string stream_source_final = stream_source_cfg;

    // If positional CLI present, prefer them (host, h264, loop)
    if (!pos.empty()) {
        // pos[0] -> hostport
        hostport_final = pos.size() > 0 ? pos[0] : hostport_final;
        if (pos.size() > 1) {
            h264_final = pos[1];
            h264_cli_set = true;
        }
        if (pos.size() > 2) {
            loop_final = (pos[2] != "0");
            loop_cli_set = true;
        }
    }

    // Override with explicit flags
    if (bitrate_cli_set) bitrate_final = bitrate_cli;
    if (nofec_cli_set) use_fec_final = !nofec_cli;
    if (log_file_cli_set) log_file_final = log_file_cli;
    if (log_level_cli_set) log_level_final = log_level_cli;
    if (stream_mode_cli_set) {
        stream_mode_final = stream_mode_cli;
        if (stream_source_cli_set) stream_source_final = stream_source_cli;
    }

    // Validate required args
    if (hostport_final.empty()) {
        std::cerr << "host:port not specified — provide as positional arg or in config\n";
        print_usage(argv[0]);
        return 1;
    }

    if (stream_mode_final && stream_source_final.empty()) {
        // if positional provided h264_final and user set --stream without source, use positional
        if (!h264_final.empty()) stream_source_final = h264_final;
    }

    if (!stream_mode_final && h264_final.empty()) {
        std::cerr << "h264 file not specified (positional arg or config.h264_file)\n";
        print_usage(argv[0]);
        return 1;
    }

    // parse host:port
    std::string host;
    int port = 8000;
    size_t colon = hostport_final.find(':');
    if (colon == std::string::npos) {
        std::cerr << "host:port required\n";
        print_usage(argv[0]);
        return 1;
    } else {
        host = hostport_final.substr(0, colon);
        std::string port_s = hostport_final.substr(colon+1);
        try {
            port = std::stoi(port_s);
        } catch (...) {
            std::cerr << "Invalid port: " << port_s << "\n";
            return 1;
        }
    }

    // parse & set log level
    if (!log_level_final.empty()) {
        desired_level = parse_log_level_or_default(log_level_final, Level::INFO);
    }
    Logger::instance().set_level(desired_level);

    // If user provided a log file, test opening it first for append/writability
    if (!log_file_final.empty()) {
        std::ofstream ofs(log_file_final.c_str(), std::ios::app);
        if (!ofs) {
            std::cerr << "Warning: could not open log file '" << log_file_final << "' for append — continuing without file logging\n";
        } else {
            ofs.close();
            Logger::instance().open_logfile(log_file_final.c_str());
        }
    }

    LOG_GEN_INFO("Starting client -> {}:{} source='{}' stream_mode={} loop={} initial_bitrate_kbps={} use_fec={}",
                 host, port,
                 stream_mode_final ? stream_source_final : h264_final,
                 stream_mode_final ? "yes" : "no",
                 loop_final ? 1 : 0,
                 bitrate_final,
                 use_fec_final ? "yes" : "no");

    // Construct client with stream flag and source/h264 file
    // Client signature:
    // Client(const std::string &host, int port, const std::string &h264Source, bool loop, bool use_fec = true, bool stream_mode = false);
    Client c(host, port, stream_mode_final ? stream_source_final : h264_final, loop_final, use_fec_final, stream_mode_final);

    if (bitrate_final > 0) {
        c.set_initial_bitrate(bitrate_final);
    }

    if (!c.run()) {
        LOG_GEN_ERROR("Client run failed");
        return 2;
    }
    return 0;
}
