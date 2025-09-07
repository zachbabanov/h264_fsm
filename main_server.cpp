#include "server.hpp"
#include "logger.hpp"
#include <iostream>

/**
 * Usage: ./server <tcp_port> [ffplay_path] [log_file]
 *
 * If log_file provided, logs will be duplicated into it.
 */
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <tcp_port> [ffplay_path] [log_file]\n";
        return 1;
    }
    int port = std::stoi(argv[1]);
    std::string player = (argc >= 3) ? argv[2] : std::string("ffplay");
    if (argc >= 4) {
        project::log::Logger::instance().open_logfile(argv[3]);
    }
    project::server::Server srv(port, player);
    if (!srv.start()) {
        LOG_GEN_ERROR("Server failed to start");
        return 1;
    }
    srv.runLoop();
    return 0;
}
