/*
* @license
* (C) zachbabanov
*
*/

#ifndef PROJECT_LOGGER_HPP
#define PROJECT_LOGGER_HPP

#pragma once

#include <iomanip>
#include <fstream>
#include <string>
#include <chrono>
#include <atomic>
#include <mutex>
#include <ctime>

#include <fmt/core.h>

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
 */
    enum class Category {
        GENERAL,
        VIDEO,
        FEC,
        PLAYER,
        NETWORK
    };

/**
 * @brief Thread-safe singleton logger using fmt for formatting.
 *
 * Usage:
 *   Logger::instance().log(Level::INFO, Category::GENERAL, "message", __FILE__, __LINE__);
 *   LOG_GEN_INFO("Hello {}", name);
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
         * @brief logf - convenience template that formats a message using fmt.
         *
         * Uses fmt::format_to with std::back_inserter to avoid conversion via internal memory_buffer->to_string.
         */
        template<typename... Args>
        void logf(Level lvl, Category cat, const char *file, int line, const char *fmt_str, Args&&... args) {
            std::string msg;
            try {
                if (fmt_str && fmt_str[0] != '\0') {
                    // Write directly into std::string via back_inserter to avoid internal buffer->string conversion
                    fmt::format_to(std::back_inserter(msg), fmt_str, std::forward<Args>(args)...);
                } else {
                    msg = "";
                }
            } catch (const std::exception &e) {
                // formatting error — fallback to raw format string + error
                try {
                    msg = fmt::format("[format_error:{}] {}", e.what(), fmt_str ? fmt_str : "");
                } catch (...) {
                    // absolute fallback
                    msg = std::string("[format_error:unknown] ") + (fmt_str ? fmt_str : "");
                }
            } catch (...) {
                // absolute fallback
                msg = std::string("[format_error:unknown] ") + (fmt_str ? fmt_str : "");
            }
            log(lvl, cat, msg, file, line);
        }

    private:
        Logger();
        ~Logger();

        std::mutex mtx_;
        std::ofstream file_;
        std::atomic<Level> min_level_;

        std::string timestamp_now();

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

#define LOG_VIDEO_TRACE(fmt, ...) project::log::Logger::instance().logf(project::log::Level::TRACE, project::log::Category::VIDEO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_VIDEO_DEBUG(fmt, ...) project::log::Logger::instance().logf(project::log::Level::DEBUG, project::log::Category::VIDEO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_VIDEO_INFO(fmt, ...) project::log::Logger::instance().logf(project::log::Level::INFO, project::log::Category::VIDEO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_VIDEO_WARN(fmt, ...) project::log::Logger::instance().logf(project::log::Level::WARN, project::log::Category::VIDEO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_VIDEO_ERROR(fmt, ...) project::log::Logger::instance().logf(project::log::Level::ERROR, project::log::Category::VIDEO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_FEC_TRACE(fmt, ...) project::log::Logger::instance().logf(project::log::Level::TRACE, project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_DEBUG(fmt, ...) project::log::Logger::instance().logf(project::log::Level::DEBUG, project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_INFO(fmt, ...)  project::log::Logger::instance().logf(project::log::Level::INFO,  project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_WARN(fmt, ...) project::log::Logger::instance().logf(project::log::Level::WARN, project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FEC_ERROR(fmt, ...) project::log::Logger::instance().logf(project::log::Level::ERROR, project::log::Category::FEC, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_PLAYER_TRACE(fmt, ...) project::log::Logger::instance().logf(project::log::Level::TRACE, project::log::Category::PLAYER, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_PLAYER_DEBUG(fmt, ...) project::log::Logger::instance().logf(project::log::Level::DEBUG, project::log::Category::PLAYER, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_PLAYER_INFO(fmt, ...) project::log::Logger::instance().logf(project::log::Level::INFO, project::log::Category::PLAYER, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_PLAYER_WARN(fmt, ...) project::log::Logger::instance().logf(project::log::Level::WARN, project::log::Category::PLAYER, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_PLAYER_ERROR(fmt, ...) project::log::Logger::instance().logf(project::log::Level::ERROR, project::log::Category::PLAYER, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_NET_TRACE(fmt, ...) project::log::Logger::instance().logf(project::log::Level::TRACE, project::log::Category::NETWORK, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_NET_DEBUG(fmt, ...) project::log::Logger::instance().logf(project::log::Level::DEBUG, project::log::Category::NETWORK, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_NET_INFO(fmt, ...) project::log::Logger::instance().logf(project::log::Level::INFO, project::log::Category::NETWORK, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_NET_WARN(fmt, ...) project::log::Logger::instance().logf(project::log::Level::WARN, project::log::Category::NETWORK, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_NET_ERROR(fmt, ...) project::log::Logger::instance().logf(project::log::Level::ERROR, project::log::Category::NETWORK, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

} // namespace project::log

#endif // PROJECT_LOGGER_HPP
