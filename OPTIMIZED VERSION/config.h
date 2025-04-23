#ifndef CONFIG_H
#define CONFIG_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <fstream>
#include "logger.h"
#include "utils.h"

// Enhanced configuration class for all client parameters
class ClientConfig {
public:
    // Server configuration
    std::string serverHostname = "18.202.148.130";
    std::vector<int> validPorts = { 49155, 3336, 8083, 8446, 3481, 65532 };
    int maxRetries = 3;
    int retryDelaySeconds = 5;
    
    // Timeout configuration
    int powTimeoutSeconds = 7200;    // 2 hours
    int defaultTimeoutSeconds = 6;   // 6 seconds
    
    // POW configuration
    long int powThreadCount = 0;     // 0 means auto (use hardware concurrency)
    long int powBatchSize = 100000;
    int powSuffixLength = 9;         // Length of random suffix for POW
    bool powUseGPU = false;          // Whether to use GPU acceleration if available
    bool powUseAdaptive = true;      // Whether to use adaptive strategy
    bool powUseHybrid = false;       // Whether to use hybrid CPU/GPU strategy
    bool detailedPowStats = true;    // Whether to show detailed POW statistics
    int powStatsInterval = 3;        // How often to show POW stats (in seconds)
    
    // POW analysis
    bool analyzePow = false;        // Whether to perform POW analysis
    int powTestDifficulty = 9;      // Difficulty to use for POW analysis
    
    // Logging configuration
    Logger::Level logLevel = Logger::INFO;
    
    // User info configuration
    bool useDefaultUserInfo = false; // Whether to use default user info
    bool promptForCertFiles = true;  // Whether to prompt for cert files
    
    // Certificate data
    std::string certData;           // Certificate data from command line or environment
    std::string keyData;            // Key data from command line or environment
    std::string certFile;           // Path to certificate file
    std::string keyFile;            // Path to key file
    
    ClientConfig() {
        // Auto-detect number of threads if not specified
        if (powThreadCount <= 0) {
            powThreadCount = std::max(1u, std::thread::hardware_concurrency());
            
            // If we have more than 1 core, reserve 1 for the main thread and OS
            if (powThreadCount > 1) {
                powThreadCount--;
            }
            
            // Use more threads than cores since POW is I/O and memory bound
            powThreadCount *= 2;
        }
        
        // Load configuration from environment variables if available
        loadFromEnvironment();
    }
    
    void loadFromEnvironment() {
        // Server configuration
        const char* host = getenv("EXATEST_HOST");
        if (host) serverHostname = host;
        
        const char* ports = getenv("EXATEST_PORTS");
        if (ports) {
            validPorts.clear();
            std::istringstream ss(ports);
            std::string port;
            while (std::getline(ss, port, ',')) {
                try {
                    validPorts.push_back(std::stoi(port));
                } catch (const std::exception&) {
                    // Ignore invalid ports
                }
            }
        }
        
        // POW configuration
        const char* threads = getenv("EXATEST_THREADS");
        if (threads) {
            try {
                powThreadCount = std::stol(threads);
            } catch (const std::exception&) {
                // Ignore invalid thread count
            }
        }
        
        const char* batchSize = getenv("EXATEST_BATCH_SIZE");
        if (batchSize) {
            try {
                powBatchSize = std::stol(batchSize);
            } catch (const std::exception&) {
                // Ignore invalid batch size
            }
        }
        
        const char* suffixLength = getenv("EXATEST_SUFFIX_LENGTH");
        if (suffixLength) {
            try {
                powSuffixLength = std::stoi(suffixLength);
            } catch (const std::exception&) {
                // Ignore invalid suffix length
            }
        }
        
        const char* useGPU = getenv("EXATEST_USE_GPU");
        if (useGPU) {
            powUseGPU = std::string(useGPU) == "1" || 
                       std::string(useGPU) == "true" || 
                       std::string(useGPU) == "yes";
        }
        
        // Certificate and key data from environment
        const char* cert = getenv("EXATEST_CERT");
        if (cert) certData = cert;
        
        const char* key = getenv("EXATEST_KEY");
        if (key) keyData = key;
        
        // Certificate and key files from environment
        const char* certFilePath = getenv("EXATEST_CERT_FILE");
        if (certFilePath) certFile = certFilePath;
        
        const char* keyFilePath = getenv("EXATEST_KEY_FILE");
        if (keyFilePath) keyFile = keyFilePath;
        
        // Load certificate and key from files if specified
        if (!certFile.empty() && !keyFile.empty()) {
            loadCertAndKeyFromFiles();
        }
    }
    
    void loadCertAndKeyFromFiles() {
        try {
            // Read certificate file
            std::ifstream certStream(certFile);
            if (!certStream.is_open()) {
                throw std::runtime_error("Failed to open certificate file: " + certFile);
            }
            
            std::stringstream certBuffer;
            certBuffer << certStream.rdbuf();
            certData = certBuffer.str();
            
            // Read key file
            std::ifstream keyStream(keyFile);
            if (!keyStream.is_open()) {
                throw std::runtime_error("Failed to open key file: " + keyFile);
            }
            
            std::stringstream keyBuffer;
            keyBuffer << keyStream.rdbuf();
            keyData = keyBuffer.str();
            
        } catch (const std::exception& e) {
            std::cerr << "Error loading certificate and key: " << e.what() << std::endl;
        }
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
                powThreadCount = std::stol(argv[++i]);
            } else if (arg == "--batch-size" && i + 1 < argc) {
                powBatchSize = std::stol(argv[++i]);
            } else if (arg == "--suffix-length" && i + 1 < argc) {
                powSuffixLength = std::stoi(argv[++i]);
            } else if (arg == "--pow-stats") {
                detailedPowStats = true;
            } else if (arg == "--pow-stats-interval" && i + 1 < argc) {
                powStatsInterval = std::stoi(argv[++i]);
            } else if (arg == "--use-gpu") {
                powUseGPU = true;
            } else if (arg == "--no-gpu") {
                powUseGPU = false;
            } else if (arg == "--use-adaptive") {
                powUseAdaptive = true;
            } else if (arg == "--no-adaptive") {
                powUseAdaptive = false;
            } else if (arg == "--use-hybrid") {
                powUseHybrid = true;
            } else if (arg == "--no-hybrid") {
                powUseHybrid = false;
            } else if (arg == "--analyze-pow") {
                analyzePow = true;
            } else if (arg == "--pow-test-difficulty" && i + 1 < argc) {
                powTestDifficulty = std::stoi(argv[++i]);
            } else if (arg == "--retries" && i + 1 < argc) {
                maxRetries = std::stoi(argv[++i]);
            } else if (arg == "--retry-delay" && i + 1 < argc) {
                retryDelaySeconds = std::stoi(argv[++i]);
            } else if (arg == "--cert-file" && i + 1 < argc) {
                certFile = argv[++i];
            } else if (arg == "--key-file" && i + 1 < argc) {
                keyFile = argv[++i];
            } else if (arg == "--cert" && i + 1 < argc) {
                certData = argv[++i];
            } else if (arg == "--key" && i + 1 < argc) {
                keyData = argv[++i];
            } else if (arg == "--use-default-info") {
                useDefaultUserInfo = true;
            } else if (arg == "--no-prompt-cert") {
                promptForCertFiles = false;
            } else if (arg == "--debug") {
                logLevel = Logger::DEBUG;
            } else if (arg == "--trace") {
                logLevel = Logger::TRACE;
            } else if (arg == "--quiet") {
                logLevel = Logger::WARNING;
            }
        }
        
        // Load certificate and key from files if specified
        if (!certFile.empty() && !keyFile.empty()) {
            loadCertAndKeyFromFiles();
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
        
        std::cout << "Connection settings:" << std::endl;
        std::cout << "  - Max retries: " << maxRetries << std::endl;
        std::cout << "  - Retry delay: " << retryDelaySeconds << " seconds" << std::endl;
        std::cout << "  - POW timeout: " << powTimeoutSeconds << " seconds" << std::endl;
        std::cout << "  - Default timeout: " << defaultTimeoutSeconds << " seconds" << std::endl;
        
        std::cout << "POW configuration: " << std::endl;
        std::cout << "  - Threads: " << powThreadCount << std::endl;
        std::cout << "  - Batch size: " << powBatchSize << std::endl;
        std::cout << "  - Suffix length: " << powSuffixLength << std::endl;
        std::cout << "  - Use GPU: " << (powUseGPU ? "Enabled" : "Disabled") << std::endl;
        std::cout << "  - Use adaptive: " << (powUseAdaptive ? "Enabled" : "Disabled") << std::endl;
        std::cout << "  - Use hybrid: " << (powUseHybrid ? "Enabled" : "Disabled") << std::endl;
        std::cout << "  - Detailed stats: " << (detailedPowStats ? "Enabled" : "Disabled") << std::endl;
        
        std::cout << "Certificate configuration:" << std::endl;
        std::cout << "  - Cert file: " << (certFile.empty() ? "Not specified" : certFile) << std::endl;
        std::cout << "  - Key file: " << (keyFile.empty() ? "Not specified" : keyFile) << std::endl;
        std::cout << "  - Cert data: " << (certData.empty() ? "Not provided" : "Provided") << std::endl;
        std::cout << "  - Key data: " << (keyData.empty() ? "Not provided" : "Provided") << std::endl;
        
        std::cout << "User info configuration:" << std::endl;
        std::cout << "  - Use default info: " << (useDefaultUserInfo ? "Yes" : "No") << std::endl;
        std::cout << "  - Prompt for cert files: " << (promptForCertFiles ? "Yes" : "No") << std::endl;
        
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
        std::cout << "Server Options:\n";
        std::cout << "  --host HOST              Set the server hostname (default: " << serverHostname << ")\n";
        std::cout << "  --ports PORT1,PORT2,...  Set the list of valid ports (comma-separated)\n";
        std::cout << "  --retries COUNT          Set the number of connection retries (default: " << maxRetries << ")\n";
        std::cout << "  --retry-delay SECONDS    Set the delay between retries in seconds (default: " << retryDelaySeconds << ")\n";
        std::cout << "  --pow-timeout SECONDS    Set the POW timeout in seconds (default: " << powTimeoutSeconds << ")\n";
        std::cout << "  --default-timeout SECONDS Set the default timeout in seconds (default: " << defaultTimeoutSeconds << ")\n";
        std::cout << "\nPOW Options:\n";
        std::cout << "  --threads COUNT          Set the number of POW worker threads (default: auto)\n";
        std::cout << "  --batch-size SIZE        Set the POW batch size (default: " << powBatchSize << ")\n";
        std::cout << "  --suffix-length LENGTH   Set the POW suffix length (default: " << powSuffixLength << ")\n";
        std::cout << "  --use-gpu               Enable GPU acceleration if available\n";
        std::cout << "  --no-gpu                Disable GPU acceleration\n";
        std::cout << "  --use-adaptive          Enable adaptive POW strategy (default: " << (powUseAdaptive ? "enabled" : "disabled") << ")\n";
        std::cout << "  --no-adaptive           Disable adaptive POW strategy\n";
        std::cout << "  --use-hybrid            Enable hybrid CPU/GPU POW strategy (default: " << (powUseHybrid ? "enabled" : "disabled") << ")\n";
        std::cout << "  --no-hybrid             Disable hybrid CPU/GPU POW strategy\n";
        std::cout << "  --pow-stats             Enable detailed POW statistics\n";
        std::cout << "  --pow-stats-interval SEC Set the interval for POW statistics (default: " << powStatsInterval << ")\n";
        std::cout << "  --analyze-pow           Analyze POW permutation space\n";
        std::cout << "  --pow-test-difficulty N Set the difficulty for POW analysis (default: " << powTestDifficulty << ")\n";
        std::cout << "\nCertificate Options:\n";
        std::cout << "  --cert-file FILE         Set the path to the certificate file\n";
        std::cout << "  --key-file FILE          Set the path to the key file\n";
        std::cout << "  --cert CERT_DATA         Set the certificate data directly\n";
        std::cout << "  --key KEY_DATA           Set the key data directly\n";
        std::cout << "  --no-prompt-cert         Don't prompt for certificate files\n";
        std::cout << "\nUser Info Options:\n";
        std::cout << "  --use-default-info       Use default user information\n";
        std::cout << "\nLogging Options:\n";
        std::cout << "  --debug                  Set log level to DEBUG\n";
        std::cout << "  --trace                  Set log level to TRACE (most verbose)\n";
        std::cout << "  --quiet                  Set log level to WARNING (less verbose)\n";
        std::cout << "  --help                   Display this help message\n";
        std::cout << "\nEnvironment Variables:\n";
        std::cout << "  EXATEST_HOST             Set the server hostname\n";
        std::cout << "  EXATEST_PORTS            Set the list of valid ports (comma-separated)\n";
        std::cout << "  EXATEST_THREADS          Set the number of POW worker threads\n";
        std::cout << "  EXATEST_BATCH_SIZE       Set the POW batch size\n";
        std::cout << "  EXATEST_SUFFIX_LENGTH    Set the POW suffix length\n";
        std::cout << "  EXATEST_USE_GPU          Enable GPU acceleration if available (1/true/yes)\n";
        std::cout << "  EXATEST_CERT             Set the certificate data directly\n";
        std::cout << "  EXATEST_KEY              Set the key data directly\n";
        std::cout << "  EXATEST_CERT_FILE        Set the path to the certificate file\n";
        std::cout << "  EXATEST_KEY_FILE         Set the path to the key file\n";
    }
};

// Global configuration
extern ClientConfig config;

#endif // CONFIG_H