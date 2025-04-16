#include "config.h"
#include <thread>

// Initialize the global configuration with default values
ClientConfig config;

// Constructor implementation could also be placed here if preferred
/*
ClientConfig::ClientConfig() {
    // Default values
    serverHostname = "18.202.148.130";
    validPorts = { 49155, 3336, 8083, 8446, 3481, 65532 };
    powTimeoutSeconds = 7200;    // 2 hours
    defaultTimeoutSeconds = 6;   // 6 seconds
    powThreadCount = (9 * std::max(1u, std::thread::hardware_concurrency()));
    powBatchSize = 100000;
    powSuffixLength = 8;         // Length of random suffix for POW
    detailedPowStats = false;    // Whether to show detailed POW statistics
    powStatsInterval = 3;        // How often to show POW stats (in seconds)
    logLevel = Logger::INFO;
}
*/