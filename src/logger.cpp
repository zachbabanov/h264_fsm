#include "logger.hpp"
#include <ctime>
#include <cstring>
#include <iostream>

namespace project::log {

Logger &Logger::instance() {
    static Logger lg;
    return lg;
}

Logger::Logger() : min_level_(Level::TRACE) {}

Logger::~Logger() {
    if (file_.is_open()) file_.close();
}

void Logger::set_level(Level l) {
    min_level_.store(l);
}

bool Logger::open_logfile(const std::string &path) {
    std::lock_guard<std::mutex> lk(mtx_);
    file_.open(path, std::ios::out | std::ios::app);
    return file_.is_open();
}
void Logger::close_logfile() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (file_.is_open()) file_.close();
}

std::string Logger::timestamp_now() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto itt = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&tm, &itt);
#else
    localtime_r(&itt, &tm);
#endif
    auto us = duration_cast<microseconds>(now.time_since_epoch()) % 1000000;
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(6) << us.count();
    return ss.str();
}

void Logger::log(Level lvl, Category cat, const std::string &msg, const char *file, int line) {
    if (lvl < min_level_.load()) return;
    std::ostringstream ss;
    ss << timestamp_now();

    const char *lvl_s = nullptr;
    switch (lvl) {
        case Level::TRACE: lvl_s = "TRACE"; break;
        case Level::DEBUG: lvl_s = "DEBUG"; break;
        case Level::INFO:  lvl_s = "INFO "; break;
        case Level::WARN:  lvl_s = "WARN "; break;
        case Level::ERROR: lvl_s = "ERROR"; break;
    }
    ss << " [" << lvl_s << "]";

    const char *cat_s = "GEN";
    switch (cat) {
        case Category::GENERAL: cat_s = "GEN"; break;
        case Category::VIDEO:   cat_s = "VIDEO"; break;
        case Category::FEC:     cat_s = "FEC"; break;
        case Category::PLAYER:  cat_s = "PLAYER"; break;
        case Category::NETWORK: cat_s = "NET"; break;
    }
    ss << " {" << cat_s << "}";

    if (file) {
        ss << " (" << file << ":" << line << ")";
    }
    ss << " - " << msg << "\n";

    std::string out = ss.str();

    std::lock_guard<std::mutex> lk(mtx_);
    std::fwrite(out.data(), 1, out.size(), stdout);
    fflush(stdout);
    if (file_.is_open()) {
        file_ << out;
        file_.flush();
    }
}

// No explicit instantiation needed; templates will instantiate as used.

} // namespace project::log
