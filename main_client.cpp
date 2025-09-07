#include "client.hpp"
#include "logger.hpp"
#include <iostream>

/**
 * Usage: ./client <host:port> <h264_file> [loop] [log_file]
 */
int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <host:port> <h264_file> [loop] [log_file]\n";
        return 1;
    }
    std::string s(argv[1]);
    auto pos = s.find(':');
    if (pos == std::string::npos) {
        std::cerr << "host:port required\n";
        return 1;
    }
    std::string host = s.substr(0, pos);
    int port = std::stoi(s.substr(pos+1));
    std::string file = argv[2];
    bool loop = (argc >= 4) ? (std::string(argv[3]) != "0") : false;
    if (argc >= 5) project::log::Logger::instance().open_logfile(argv[4]);

    project::client::Client c(host, port, file, loop);
    if (!c.run()) {
        std::cerr << "Client failed\n";
        return 1;
    }
    return 0;
}
