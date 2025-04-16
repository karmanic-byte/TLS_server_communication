#ifndef CONFIG_H
#define CONFIG_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include "logger.h"
#include "utils.h"

// Configuration class for all client parameters
class ClientConfig {
public:
    // Default values
    std::string serverHostname = "18.202.148.130";
    std::vector<int> validPorts = { 49155, 3336, 8083, 8446, 3481, 65532 };
    int powTimeoutSeconds = 7200;    // 2 hours
    int defaultTimeoutSeconds = 6;   // 6 seconds
    long int powThreadCount = (9000 * std::max(1u, std::thread::hardware_concurrency()));
    long int powBatchSize = 100000;
    int powSuffixLength = 8;         // Length of random suffix for POW
    bool detailedPowStats = false;   // Whether to show detailed POW statistics
    int powStatsInterval = 3;        // How often to show POW stats (in seconds)
    Logger::Level logLevel = Logger::INFO;
    
    ClientConfig() {
        // Initialize with default values
    }
    
    void updateFromArgs(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "--host" && i + 1 < argc) {
                serverHostname = argv[++i];
            } else if (arg == "--ports" && i + 1 < argc) {
                validPorts.clear();
                std::string portsStr = argv[++i];
                std::stringstream ss(portsStr);
                std::string port;
                while (std::getline(ss, port, ',')) {
                    try {
                        validPorts.push_back(std::stoi(port));
                    } catch (const std::exception& e) {
                        // Ignore invalid ports
                    }
                }
            } else if (arg == "--pow-timeout" && i + 1 < argc) {
                powTimeoutSeconds = std::stoi(argv[++i]);
            } else if (arg == "--default-timeout" && i + 1 < argc) {
                defaultTimeoutSeconds = std::stoi(argv[++i]);
            } else if (arg == "--threads" && i + 1 < argc) {
                powThreadCount = std::stoi(argv[++i]);
            } else if (arg == "--batch-size" && i + 1 < argc) {
                powBatchSize = std::stoi(argv[++i]);
            } else if (arg == "--suffix-length" && i + 1 < argc) {
                powSuffixLength = std::stoi(argv[++i]);
            } else if (arg == "--pow-stats") {
                detailedPowStats = true;
            } else if (arg == "--pow-stats-interval" && i + 1 < argc) {
                powStatsInterval = std::stoi(argv[++i]);
            } else if (arg == "--debug") {
                logLevel = Logger::DEBUG;
            } else if (arg == "--trace") {
                logLevel = Logger::TRACE;
            } else if (arg == "--quiet") {
                logLevel = Logger::WARNING;
            }
        }
        
        // Update logger level
        logger.setLevel(logLevel);
    }
    
    void printConfig() {
        std::cout << Color::BOLD << Color::CYAN << "\n";
        std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                   Exatest Protocol Client                     ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
        std::cout << Color::RESET << std::endl;
        
        std::cout << "Target host: " << Color::BOLD << serverHostname << Color::RESET << std::endl;
        
        std::cout << "Valid ports: ";
        for (size_t i = 0; i < validPorts.size(); ++i) {
            std::cout << validPorts[i];
            if (i < validPorts.size() - 1) std::cout << ", ";
        }
        std::cout << std::endl;
        
        std::cout << "POW configuration: " << std::endl;
        std::cout << "  - Threads: " << powThreadCount << std::endl;
        std::cout << "  - Batch size: " << powBatchSize << std::endl;
        std::cout << "  - Suffix length: " << powSuffixLength << std::endl;
        std::cout << "  - Timeout: " << powTimeoutSeconds << " seconds" << std::endl;
        std::cout << "  - Detailed stats: " << (detailedPowStats ? "Enabled" : "Disabled") << std::endl;
        
        std::cout << "Log level: ";
        switch (logLevel) {
            case Logger::TRACE: std::cout << "TRACE"; break;
            case Logger::DEBUG: std::cout << "DEBUG"; break;
            case Logger::INFO: std::cout << "INFO"; break;
            case Logger::WARNING: std::cout << "WARNING"; break;
            case Logger::LEVEL_ERROR: std::cout << "ERROR"; break;
            case Logger::NONE: std::cout << "NONE"; break;
        }
        std::cout << std::endl << std::endl;
    }
    
    void printHelp(const char* program) {
        std::cout << "Usage: " << program << " [options]\n\n";
        std::cout << "Options:\n";
        std::cout << "  --host HOST              Set the server hostname (default: " << serverHostname << ")\n";
        std::cout << "  --ports PORT1,PORT2,...  Set the list of valid ports (comma-separated)\n";
        std::cout << "  --pow-timeout SECONDS    Set the POW timeout in seconds (default: " << powTimeoutSeconds << ")\n";
        std::cout << "  --default-timeout SECONDS Set the default timeout in seconds (default: " << defaultTimeoutSeconds << ")\n";
        std::cout << "  --threads COUNT          Set the number of POW worker threads (default: " << powThreadCount << ")\n";
        std::cout << "  --batch-size SIZE        Set the POW batch size (default: " << powBatchSize << ")\n";
        std::cout << "  --suffix-length LENGTH   Set the POW suffix length (default: " << powSuffixLength << ")\n";
        std::cout << "  --pow-stats              Enable detailed POW statistics\n";
        std::cout << "  --pow-stats-interval SEC Set the interval for POW statistics (default: " << powStatsInterval << ")\n";
        std::cout << "  --debug                  Set log level to DEBUG\n";
        std::cout << "  --trace                  Set log level to TRACE (most verbose)\n";
        std::cout << "  --quiet                  Set log level to WARNING (less verbose)\n";
        std::cout << "  --help                   Display this help message\n";
    }
};

// Global configuration
extern ClientConfig config;

#endif // CONFIG_H