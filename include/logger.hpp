#ifndef PROJECT_LOGGER_HPP
#define PROJECT_LOGGER_HPP

#pragma once

#include <string>
#include <mutex>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <atomic>

namespace project::log {

/**
 * @brief Log level enumeration
 */
enum class Level {
    TRACE = 0,
    DEBUG,
    INFO,
    WARN,
    ERROR
};

/**
 * @brief Categories to attach to each log line.
 *
 * These categories help separate metrics/logs for QoS/experiments.
 */
enum class Category {
    GENERAL,
    VIDEO,
    FEC,
    PLAYER,
    NETWORK
};

/**
 * @brief Thread-safe singleton logger.
 *
 * Provides:
 *  - timestamped logging
 *  - categories and levels
 *  - optional file logging
 *  - a small variadic-format helper that replaces first {} in format string
 *
 * Usage:
 *   Logger::instance().log(Level::INFO, Category::GENERAL, "message", __FILE__, __LINE__);
 */
class Logger {
public:
    static Logger &instance();

    /// Set global minimal log level (messages below will be ignored)
    void set_level(Level l);

    /// Open file to duplicate logs into
    bool open_logfile(const std::string &path);

    /// Close log file
    void close_logfile();

    /// Core logging call: prints a ready message
    void log(Level lvl, Category cat, const std::string &msg, const char *file = nullptr, int line = 0);

    /**
     * @brief logf - convenience template that formats a message.
     *
     * Very small formatting: replaces the first format occurrence ("{}" or "%s" or "%d")
     * with each provided argument in order.
     */
    template<typename... Args>
    void logf(Level lvl, Category cat, const char *file, int line, const char *fmt, Args... args) {
        std::ostringstream ss;
        format_to_stream(ss, fmt, args...);
        log(lvl, cat, ss.str(), file, line);
    }

private:
    Logger();
    ~Logger();

    std::mutex mtx_;
    std::ofstream file_;
    std::atomic<Level> min_level_;

    std::string timestamp_now();

    // formatting helpers
    void format_to_stream(std::ostringstream &oss, const char *fmt) {
        if (fmt && fmt[0] != '\0') oss << fmt;
    }

    template<typename T, typename... Rest>
    void format_to_stream(std::ostringstream &oss, const char *fmt, T value, Rest... rest) {
        // Replace first placeholder with the value; very small formatting helper.
        std::string s(fmt ? fmt : "");
        size_t pos = s.find("{}");
        if (pos == std::string::npos) pos = s.find("%s");
        if (pos == std::string::npos) pos = s.find("%d");
        if (pos == std::string::npos) {
            // No placeholder: append fmt and then value
            oss << s << " " << value;
            format_to_stream(oss, "", rest...);
            return;
        }
        oss << s.substr(0, pos);
        oss << value;
        std::string rest_fmt = s.substr(pos + 2);
        format_to_stream(oss, rest_fmt.c_str(), rest...);
    }
    // non-copyable
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
};

// Convenience macros for easy calls (automatically add file:line)
#define LOG_GEN_TRACE(fmt, ...) project::log::Logger::instance().logf(project::log::Level::TRACE, project::log::Category::GENERAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_GEN_DEBUG(fmt, ...) project::log::Logger::instance().logf(project::log::Level::DEBUG, project::log::Category::GENERAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_GEN_INFO(fmt, ...)  project::log::Logger::instance().logf(project::log::Level::INFO,  project::log::Category::GENERAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_GEN_WARN(fmt, ...)  project::log::Logger::instance().logf(project::log::Level::WARN,  project::log::Category::GENERAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_GEN_ERROR(fmt, ...) project::log::Logger::instance().logf(project::log::Level::ERROR, project::log::Category::GENERAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_VIDEO_INFO(fmt, ...) project::log::Logger::instance().logf(project::log::Level::INFO, project::log::Category::VIDEO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_VIDEO_DEBUG(fmt, ...) project::log::Logger::instance().logf(project::log::Level::DEBUG, project::log::Category::VIDEO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_INFO(fmt, ...) project::log::Logger::instance().logf(project::log::Level::INFO, project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_WARN(fmt, ...)  project::log::Logger::instance().logf(project::log::Level::WARN,  project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_DEBUG(fmt, ...) project::log::Logger::instance().logf(project::log::Level::DEBUG, project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_ERROR(fmt, ...) project::log::Logger::instance().logf(project::log::Level::ERROR, project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_PLAYER_INFO(fmt, ...) project::log::Logger::instance().logf(project::log::Level::INFO, project::log::Category::PLAYER, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_NET_INFO(fmt, ...) project::log::Logger::instance().logf(project::log::Level::INFO, project::log::Category::NETWORK, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_NET_WARN(fmt, ...) project::log::Logger::instance().logf(project::log::Level::WARN, project::log::Category::NETWORK, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

} // namespace project::log

#endif // PROJECT_LOGGER_HPP
