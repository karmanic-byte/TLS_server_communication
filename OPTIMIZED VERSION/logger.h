#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <string>
#include <mutex>
#include "utils.h"

// Logger class with thread safety and configurable levels
class Logger {
public:
    enum Level {
        TRACE,
        DEBUG,
        INFO,
        WARNING,
        LEVEL_ERROR,
        NONE
    };

    Logger(Level level = INFO) : m_level(level) {}

    void setLevel(Level level) {
        m_level = level;
    }

    void trace(const std::string& message) {
        if (m_level <= TRACE) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cout << Color::DIM << Color::MAGENTA << "[TRACE] " << message << Color::RESET << std::endl;
        }
    }

    void debug(const std::string& message) {
        if (m_level <= DEBUG) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cout << Color::DIM << "[DEBUG] " << message << Color::RESET << std::endl;
        }
    }

    void info(const std::string& message) {
        if (m_level <= INFO) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cout << Color::BLUE << "[INFO] " << message << Color::RESET << std::endl;
        }
    }

    void warning(const std::string& message) {
        if (m_level <= WARNING) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cout << Color::YELLOW << "[WARNING] " << message << Color::RESET << std::endl;
        }
    }

    void error(const std::string& message) {
        if (m_level <= ERROR) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cerr << Color::RED << "[ERROR] " << message << Color::RESET << std::endl;
        }
    }

    void success(const std::string& message) {
        if (m_level <= INFO) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cout << Color::GREEN << "[SUCCESS] " << message << Color::RESET << std::endl;
        }
    }

    void header(const std::string& message) {
        if (m_level <= INFO) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cout << std::endl << Color::BOLD << Color::CYAN 
                      << "==== " << message << " ====" 
                      << Color::RESET << std::endl;
        }
    }

    void command(const std::string& direction, const std::string& command, const std::string& data = "") {
        if (m_level <= DEBUG) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (direction == "<<<") {
                std::cout << Color::GREEN << direction << " " << Color::BOLD << command;
            } else {
                std::cout << Color::YELLOW << direction << " " << Color::BOLD << command;
            }
            
            if (!data.empty()) {
                std::cout << Color::RESET << " " << data;
            }
            std::cout << Color::RESET << std::endl;
        }
    }

    void powStats(uint64_t attempts, uint64_t rate, const std::string& bestHash, int duration) {
        if (m_level <= DEBUG) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cout << Color::CYAN << "[POW] " 
                      << "Attempts: " << attempts 
                      << " | Rate: " << rate << " H/s"
                      << " | Best hash: " << bestHash
                      << " | Duration: " << duration << "s"
                      << Color::RESET << std::endl;
        }
    }

private:
    Level m_level;
    std::mutex m_mutex;
};

// Global logger instance
extern Logger logger;

#endif // LOGGER_H