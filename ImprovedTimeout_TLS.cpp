

/**
 * Optimized TLS Protocol Client
 * 
 * A highly optimized client for communicating with the Exatest server:
 * - Highly optimized multi-threaded POW solver with advanced techniques
 * - Proper TLS certificate handling
 * - Robust timeout management (POW: 2 hours, others: 6 seconds)
 * - Automatic port selection from available options
 * - UTF-8 validation and handling
 * - Line-oriented protocol implementation
 * - Enhanced debugging and POW performance monitoring
 * - Configurable parameters through command-line options
 * 
 * Compilation:
 * g++ -Wall -Wextra -g3 -O3 -std=c++17 optimized_tls_client.cpp -o optimized_tls_client.exe -lssl -lcrypto -lws2_32 -pthread
 */

 #include <iostream>
 #include <string>
 #include <vector>
 #include <map>
 #include <set>
 #include <queue>
 #include <atomic>
 #include <thread>
 #include <mutex>
 #include <condition_variable>
 #include <chrono>
 #include <algorithm>
 #include <iomanip>
 #include <sstream>
 #include <fstream>
 #include <cctype>
 #include <cstring>
 #include <random>
 #include <memory>
 #include <functional>
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 #include <openssl/sha.h>
 #include <openssl/bio.h>
 #include <openssl/pem.h>
 #include <openssl/rand.h>
 #include <openssl/evp.h>
 
 // Windows-specific networking headers
 #include <winsock2.h>
 #include <ws2tcpip.h>
 #include <windows.h>
 
 // ANSI color codes for terminal output
 namespace Color {
     const std::string RESET = "\033[0m";
     const std::string RED = "\033[31m";
     const std::string GREEN = "\033[32m";
     const std::string YELLOW = "\033[33m";
     const std::string BLUE = "\033[34m";
     const std::string MAGENTA = "\033[35m";
     const std::string CYAN = "\033[36m";
     const std::string BOLD = "\033[1m";
     const std::string DIM = "\033[2m";
 }
 
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
 
 // Global logger
 Logger logger;
 
 // Configuration class for all client parameters
 class ClientConfig {
 public:
     // Default values
     std::string serverHostname = "18.202.148.130";
     std::vector<int> validPorts = { 49155, 3336, 8083, 8446, 3481, 65532 };
     int powTimeoutSeconds = 7200;    // 2 hours
     int defaultTimeoutSeconds = 6;   // 6 seconds
     int powThreadCount = (9 * std::max(1u, std::thread::hardware_concurrency()));
     int powBatchSize = 100000;
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
 ClientConfig config;
 
 // Set of valid country names
 class CountryList {
 public:
     CountryList() {
         // Initialize with the list of country names from the specified source
         m_countries = {
             "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Antigua and Barbuda", 
             "Argentina", "Armenia", "Australia", "Austria", "Azerbaijan", "Bahamas", "Bahrain", 
             "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bhutan", 
             "Bolivia", "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei", "Bulgaria", 
             "Burkina Faso", "Burundi", "Cabo Verde", "Cambodia", "Cameroon", "Canada", 
             "Central African Republic", "Chad", "Chile", "China", "Colombia", "Comoros", 
             "Congo", "Costa Rica", "Cote d'Ivoire", "Croatia", "Cuba", "Cyprus", 
             "Czech Republic", "Denmark", "Djibouti", "Dominica", "Dominican Republic", 
             "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", 
             "Eswatini", "Ethiopia", "Fiji", "Finland", "France", "Gabon", "Gambia", "Georgia", 
             "Germany", "Ghana", "Greece", "Grenada", "Guatemala", "Guinea", "Guinea-Bissau", 
             "Guyana", "Haiti", "Honduras", "Hungary", "Iceland", "India", "Indonesia", "Iran", 
             "Iraq", "Ireland", "Israel", "Italy", "Jamaica", "Japan", "Jordan", "Kazakhstan", 
             "Kenya", "Kiribati", "Korea, North", "Korea, South", "Kosovo", "Kuwait", "Kyrgyzstan", 
             "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya", "Liechtenstein", 
             "Lithuania", "Luxembourg", "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", 
             "Malta", "Marshall Islands", "Mauritania", "Mauritius", "Mexico", "Micronesia", 
             "Moldova", "Monaco", "Mongolia", "Montenegro", "Morocco", "Mozambique", "Myanmar", 
             "Namibia", "Nauru", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger", 
             "Nigeria", "North Macedonia", "Norway", "Oman", "Pakistan", "Palau", "Palestine", 
             "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", "Poland", "Portugal", 
             "Qatar", "Romania", "Russia", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia", 
             "Saint Vincent and the Grenadines", "Samoa", "San Marino", "Sao Tome and Principe", 
             "Saudi Arabia", "Senegal", "Serbia", "Seychelles", "Sierra Leone", "Singapore", 
             "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa", "South Sudan", 
             "Spain", "Sri Lanka", "Sudan", "Suriname", "Sweden", "Switzerland", "Syria", "Taiwan", 
             "Tajikistan", "Tanzania", "Thailand", "Timor-Leste", "Togo", "Tonga", 
             "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Tuvalu", "Uganda", 
             "Ukraine", "United Arab Emirates", "United Kingdom", "United States", "Uruguay", 
             "Uzbekistan", "Vanuatu", "Vatican City", "Venezuela", "Vietnam", "Yemen", "Zambia", 
             "Zimbabwe"
         };
     }
 
     const std::set<std::string>& getCountries() const {
         return m_countries;
     }
 
     bool isValid(const std::string& country) const {
         return m_countries.find(country) != m_countries.end();
     }
 
 private:
     std::set<std::string> m_countries;
 };
 
 // Utility functions for common operations
 namespace Utils {
     // Convert byte array to hex string
     std::string bytesToHex(const unsigned char* data, size_t len) {
         std::stringstream ss;
         ss << std::hex << std::setfill('0');
         for (size_t i = 0; i < len; i++) {
             ss << std::setw(2) << static_cast<int>(data[i]);
         }
         return ss.str();
     }
 
     // Compute SHA-1 hash
     std::string sha1(const std::string& input) {
         unsigned char hash[SHA_DIGEST_LENGTH];
         SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
         return bytesToHex(hash, SHA_DIGEST_LENGTH);
     }
 
     // Compute SHA-1 hash with OpenSSL EVP interface for better performance
     std::string sha1_evp(const std::string& input) {
         unsigned char hash[SHA_DIGEST_LENGTH];
         EVP_MD_CTX* context = EVP_MD_CTX_new();
         
         EVP_DigestInit_ex(context, EVP_sha1(), NULL);
         EVP_DigestUpdate(context, input.c_str(), input.length());
         EVP_DigestFinal_ex(context, hash, NULL);
         
         EVP_MD_CTX_free(context);
         
         return bytesToHex(hash, SHA_DIGEST_LENGTH);
     }
 
     // Generate random string for POW - avoiding \n\r\t and space as required
     std::string randomPowString(size_t length, std::mt19937& gen) {
         static const char allowed_chars[] =
             "0123456789"
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // All printable ASCII except space, tab, newline
         
         const int char_count = sizeof(allowed_chars) - 1;
         std::uniform_int_distribution<> dist(0, char_count - 1);
         
         std::string result;
         result.reserve(length);
         
         for (size_t i = 0; i < length; ++i) {
             result += allowed_chars[dist(gen)];
         }
         
         return result;
     }
 
     // Check if string is valid UTF-8
     bool isValidUTF8(const std::string& str) {
         const unsigned char* bytes = (const unsigned char*)str.c_str();
         size_t len = str.length();
         
         for (size_t i = 0; i < len; i++) {
             if (bytes[i] <= 0x7F) {
                 // Single byte character
                 continue;
             } else if ((bytes[i] & 0xE0) == 0xC0) {
                 // 2-byte sequence
                 if (i + 1 >= len || (bytes[i+1] & 0xC0) != 0x80) {
                     return false;
                 }
                 i += 1;
             } else if ((bytes[i] & 0xF0) == 0xE0) {
                 // 3-byte sequence
                 if (i + 2 >= len || (bytes[i+1] & 0xC0) != 0x80 || 
                     (bytes[i+2] & 0xC0) != 0x80) {
                     return false;
                 }
                 i += 2;
             } else if ((bytes[i] & 0xF8) == 0xF0) {
                 // 4-byte sequence
                 if (i + 3 >= len || (bytes[i+1] & 0xC0) != 0x80 || 
                     (bytes[i+2] & 0xC0) != 0x80 || (bytes[i+3] & 0xC0) != 0x80) {
                     return false;
                 }
                 i += 3;
             } else {
                 // Invalid UTF-8 lead byte
                 return false;
             }
         }
         
         return true;
     }
 
     // Convert string to UTF-8 if needed
     std::string ensureUTF8(const std::string& input) {
         if (isValidUTF8(input)) {
             return input;
         }
         
         // If not valid UTF-8, replace invalid sequences with '?'
         std::string result;
         const unsigned char* bytes = (const unsigned char*)input.c_str();
         size_t len = input.length();
         
         for (size_t i = 0; i < len; i++) {
             if (bytes[i] <= 0x7F) {
                 // ASCII character
                 result += bytes[i];
             } else {
                 // Replace non-UTF-8 with '?'
                 result += '?';
             }
         }
         
         return result;
     }
 
     // Parse command from line
     std::pair<std::string, std::string> parseCommand(const std::string& line) {
         size_t spacePos = line.find(' ');
         if (spacePos == std::string::npos) {
             return std::make_pair(line, "");
         }
         
         std::string command = line.substr(0, spacePos);
         std::string args = line.substr(spacePos + 1);
         
         return std::make_pair(command, args);
     }
 
     // Save cert and key to temporary files
     std::pair<std::string, std::string> saveCertAndKey(const std::string& cert, const std::string& key) {
         std::string certFile = "temp_cert_" + std::to_string(GetCurrentProcessId()) + ".pem";
         std::string keyFile = "temp_key_" + std::to_string(GetCurrentProcessId()) + ".pem";
         
         std::ofstream certOut(certFile);
         if (!certOut.is_open()) {
             throw std::runtime_error("Failed to create temporary certificate file");
         }
         certOut << cert;
         certOut.close();
         
         std::ofstream keyOut(keyFile);
         if (!keyOut.is_open()) {
             throw std::runtime_error("Failed to create temporary key file");
         }
         keyOut << key;
         keyOut.close();
         
         return std::make_pair(certFile, keyFile);
     }
 
     // Clean up temporary files
     void cleanupTempFiles(const std::string& certFile, const std::string& keyFile) {
         remove(certFile.c_str());
         remove(keyFile.c_str());
     }
 }
 
 // Thread-safe job queue for worker threads
 template<typename T>
 class JobQueue {
 public:
     bool push(T item) {
         std::unique_lock<std::mutex> lock(m_mutex);
         if (m_shutdown) {
             return false;
         }
         m_queue.push(item);
         m_condition.notify_one();
         return true;
     }
 
     bool pop(T& item) {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_condition.wait(lock, [this] { return !m_queue.empty() || m_shutdown; });
         
         if (m_queue.empty()) {
             return false;
         }
         
         item = m_queue.front();
         m_queue.pop();
         return true;
     }
 
     void shutdown() {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_shutdown = true;
         m_condition.notify_all();
     }
 
     bool empty() const {
         std::unique_lock<std::mutex> lock(m_mutex);
         return m_queue.empty();
     }
 
     size_t size() const {
         std::unique_lock<std::mutex> lock(m_mutex);
         return m_queue.size();
     }
 
 private:
     std::queue<T> m_queue;
     mutable std::mutex m_mutex;
     std::condition_variable m_condition;
     bool m_shutdown = false;
 };
 
 // Thread pool for parallel POW computation with enhanced performance monitoring
 class POWThreadPool {
 public:
     POWThreadPool(int numThreads, const std::string& challenge, int difficulty) 
         : m_challenge(challenge), m_difficulty(difficulty), m_targetPrefix(difficulty, '0'),
           m_running(true), m_found(false), m_totalAttempts(0), m_bestZeroCount(0) {
         
         logger.info("Initializing POW solver with " + std::to_string(numThreads) + " threads");
         logger.info("Challenge: " + challenge);
         logger.info("Difficulty: " + std::to_string(difficulty) + " (target: " + m_targetPrefix + "...)");
         
         m_startTime = std::chrono::high_resolution_clock::now();
         
         // Start the worker threads
         for (int i = 0; i < numThreads; ++i) {
             m_threads.emplace_back(&POWThreadPool::workerThread, this, i);
         }
         
         // Start the statistics thread if enabled
         if (config.detailedPowStats) {
             m_statsThread = std::thread(&POWThreadPool::statsThread, this);
         }
     }
     
     ~POWThreadPool() {
         // Signal all threads to stop
         {
             std::lock_guard<std::mutex> lock(m_mutex);
             m_running = false;
         }
         m_condition.notify_all();
         
         // Wait for all threads to finish
         for (auto& thread : m_threads) {
             if (thread.joinable()) {
                 thread.join();
             }
         }
         
         // Stop the statistics thread if it's running
         if (config.detailedPowStats && m_statsThread.joinable()) {
             m_statsThread.join();
         }
         
         // Print final statistics
         auto endTime = std::chrono::high_resolution_clock::now();
         auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - m_startTime).count();
         
         uint64_t hashRate = (duration > 0) ? (m_totalAttempts.load() / duration) : 0;
         
         logger.info("POW solve completed with " + std::to_string(m_totalAttempts.load()) + " attempts");
         logger.info("Average hash rate: " + std::to_string(hashRate) + " hashes/second");
         logger.info("Total duration: " + std::to_string(duration) + " seconds");
     }
     
     // Wait for a solution
     std::string waitForSolution() {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_condition.wait(lock, [this] { return m_found || !m_running; });
         
         if (m_found) {
             auto endTime = std::chrono::high_resolution_clock::now();
             auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - m_startTime).count();
             
             logger.success("POW solution found in " + std::to_string(duration) + " seconds");
             logger.success("Solution: " + m_solution);
             logger.success("Hash: " + Utils::sha1(m_challenge + m_solution));
             
             return m_solution;
         }
         
         return "";
     }
 
 private:
     // Thread that periodically reports POW solving statistics
     void statsThread() {
         logger.debug("POW statistics thread started");
         
         while (true) {
             {
                 std::unique_lock<std::mutex> lock(m_mutex);
                 if (!m_running || m_found) {
                     break;
                 }
             }
             
             // Sleep for the statistics interval
             std::this_thread::sleep_for(std::chrono::seconds(config.powStatsInterval));
             
             // Calculate statistics
             auto now = std::chrono::high_resolution_clock::now();
             auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime).count();
             
             uint64_t attempts = m_totalAttempts.load();
             uint64_t rate = (duration > 0) ? (attempts / duration) : 0;
             
             std::string bestHashInfo;
             {
                 std::lock_guard<std::mutex> lock(m_mutex);
                 bestHashInfo = m_bestHash.substr(0, std::min(size_t(16), m_bestHash.length())) + 
                               " (" + std::to_string(m_bestZeroCount) + " zeros)";
             }
             
             // Log statistics
             logger.powStats(attempts, rate, bestHashInfo, duration);
         }
         
         logger.debug("POW statistics thread exiting");
     }
     
     void workerThread(int id) {
         logger.debug("POW Worker thread " + std::to_string(id) + " started");
         
         // Initialize thread-local random number generator with a unique seed
         std::random_device rd;
         std::mt19937 gen(rd() + id * 1000); // Add thread ID to seed for better distribution
         
         const int suffixLength = config.powSuffixLength;
         uint64_t localAttempts = 0;
         int localBestZeros = 0;
         std::string localBestHash;
         std::string localBestSuffix;
         
         while (true) {
             // Check if we should stop
             {
                 std::lock_guard<std::mutex> lock(m_mutex);
                 if (!m_running || m_found) {
                     break;
                 }
             }
             
             // Process a batch of random strings
             for (int i = 0; i < config.powBatchSize; ++i) {
                 // Generate random suffix
                 std::string suffix = Utils::randomPowString(suffixLength, gen);
                 
                 // Compute SHA-1 hash using the optimized EVP interface
                 std::string hash = Utils::sha1_evp(m_challenge + suffix);
                 
                 // Increment attempt counter
                 localAttempts++;
                 
                 // Check if hash meets the difficulty requirement
                 if (hash.compare(0, m_difficulty, m_targetPrefix) == 0) {
                     // Found a solution!
                     std::lock_guard<std::mutex> lock(m_mutex);
                     if (!m_found) {
                         m_found = true;
                         m_solution = suffix;
                         logger.success("POW Worker " + std::to_string(id) + " found solution: " + suffix);
                         logger.debug("Hash: " + hash);
                     }
                     m_condition.notify_all();
                     m_totalAttempts += localAttempts;
                     return;
                 }
                 
                 // Track the best hash we've seen so far (for reporting)
                 int zeroCount = 0;
                 while (zeroCount < hash.length() && hash[zeroCount] == '0') {
                     zeroCount++;
                 }
                 
                 if (zeroCount > localBestZeros) {
                     localBestZeros = zeroCount;
                     localBestHash = hash;
                     localBestSuffix = suffix;
                     
                     // If this is better than the best we've seen globally, update that too
                     std::lock_guard<std::mutex> lock(m_mutex);
                     if (zeroCount > m_bestZeroCount) {
                         m_bestZeroCount = zeroCount;
                         m_bestHash = hash;
                         m_bestSuffix = suffix;
                         
                         // Log significant improvements
                         if (zeroCount >= m_difficulty - 2) {
                             logger.debug("Thread " + std::to_string(id) + " found hash with " + 
                                         std::to_string(zeroCount) + " leading zeros: " + hash);
                         }
                     }
                 }
             }
             
             // Update total attempts counter periodically
             m_totalAttempts += localAttempts;
             localAttempts = 0;
             
             // Periodically check if another thread found a solution
             {
                 std::lock_guard<std::mutex> lock(m_mutex);
                 if (m_found || !m_running) {
                     break;
                 }
             }
         }
         
         // Add remaining attempts to the total
         if (localAttempts > 0) {
             m_totalAttempts += localAttempts;
         }
         
         logger.debug("POW Worker thread " + std::to_string(id) + " exiting");
     }
     
     std::string m_challenge;
     int m_difficulty;
     std::string m_targetPrefix;
     std::vector<std::thread> m_threads;
     std::thread m_statsThread;
     std::mutex m_mutex;
     std::condition_variable m_condition;
     std::atomic<bool> m_running;
     bool m_found;
     std::string m_solution;
     std::atomic<uint64_t> m_totalAttempts;
     int m_bestZeroCount;
     std::string m_bestHash;
     std::string m_bestSuffix;
     std::chrono::time_point<std::chrono::high_resolution_clock> m_startTime;
 }; 

// Enhanced Client class for the Exatest protocol with improved user input hand
class ExatestClient {
    public:
        struct UserInfo {
            std::string name;
            std::vector<std::string> emails;
            std::string skype;
            std::string birthdate;
            std::string country;
            std::vector<std::string> addressLines;
            
            // Constructor with default values
            UserInfo() {
                // Default values can be overridden by user input
                name = "Default User";
                emails = {"default@example.com"};
                skype = "default.skype";
                birthdate = "01.01.1990";  // Format: DD.MM.YYYY
                country = "United States";
                addressLines = {"123 Default St", "Default City, 12345"};
            }
            
            // Validate user information
            bool validate(std::vector<std::string>& errors) const {
                bool valid = true;
                CountryList countryList;
                
                // Validate name
                if (name.empty()) {
                    errors.push_back("Name cannot be empty");
                    valid = false;
                }
                
                // Validate emails
                if (emails.empty()) {
                    errors.push_back("At least one email address is required");
                    valid = false;
                } else {
                    for (const auto& email : emails) {
                        if (email.find('@') == std::string::npos) {
                            errors.push_back("Invalid email address: " + email);
                            valid = false;
                            break;
                        }
                    }
                }
                
                // Validate birthdate (simple format check)
                if (birthdate.length() != 10 || 
                    birthdate[2] != '.' || 
                    birthdate[5] != '.') {
                    errors.push_back("Birthdate must be in DD.MM.YYYY format");
                    valid = false;
                }
                
                // Validate country
                if (!countryList.isValid(country)) {
                    errors.push_back("Invalid country name: " + country);
                    valid = false;
                }
                
                // Validate address
                if (addressLines.empty()) {
                    errors.push_back("At least one address line is required");
                    valid = false;
                }
                
                return valid;
            }
            
            // Helper method to collect user info interactively
            static UserInfo collectFromUser() {
                UserInfo info;
                CountryList countryList;
                
                std::cout << "\n" << Color::BOLD << "Please enter your information:" << Color::RESET << "\n";
                
                std::cout << "Full name: ";
                std::getline(std::cin, info.name);
                
                // Email addresses
                int emailCount = 0;
                std::cout << "How many email addresses do you want to provide? ";
                std::cin >> emailCount;
                std::cin.ignore(); // Clear the newline
                
                info.emails.clear();
                for (int i = 0; i < emailCount; i++) {
                    std::string email;
                    std::cout << "Email " << (i+1) << ": ";
                    std::getline(std::cin, email);
                    info.emails.push_back(email);
                }
                
                std::cout << "Skype ID: ";
                std::getline(std::cin, info.skype);
                
                std::cout << "Birthdate (DD.MM.YYYY): ";
                std::getline(std::cin, info.birthdate);
                
                // Country selection
                bool validCountry = false;
                while (!validCountry) {
                    std::cout << "Country: ";
                    std::getline(std::cin, info.country);
                    
                    validCountry = countryList.isValid(info.country);
                    if (!validCountry) {
                        std::cout << Color::RED << "Invalid country name. Please try again." << Color::RESET << "\n";
                    }
                }
                
                // Address lines
                int addressLineCount = 0;
                std::cout << "How many address lines do you want to provide? ";
                std::cin >> addressLineCount;
                std::cin.ignore(); // Clear the newline
                
                info.addressLines.clear();
                for (int i = 0; i < addressLineCount; i++) {
                    std::string addressLine;
                    std::cout << "Address line " << (i+1) << ": ";
                    std::getline(std::cin, addressLine);
                    info.addressLines.push_back(addressLine);
                }
                
                // Validate and report any issues
                std::vector<std::string> errors;
                if (!info.validate(errors)) {
                    std::cout << Color::RED << "There are validation issues with your information:" << Color::RESET << "\n";
                    for (const auto& error : errors) {
                        std::cout << "- " << error << "\n";
                    }
                    std::cout << "Please correct these issues and try again.\n";
                    return collectFromUser(); // Recursively collect again
                }
                
                return info;
            }
        };
        
        ExatestClient(const std::string& hostname, 
                    const std::string& cert,
                    const std::string& key,
                    const UserInfo& userInfo)
            : m_hostname(hostname), 
              m_cert(cert), 
              m_key(key),
              m_userInfo(userInfo),
              m_connected(false), 
              m_port(0),
              m_lastSuccessfulPort(0) {}
        
        ~ExatestClient() {
            disconnect();
            
            // Clean up temporary files if they exist
            if (!m_certFile.empty() && !m_keyFile.empty()) {
                Utils::cleanupTempFiles(m_certFile, m_keyFile);
            }
        }
        
        bool connect(int maxRetries = 3, int retryDelaySeconds = 5) {
            // Save certificate and key to temporary files
            try {
                auto files = Utils::saveCertAndKey(m_cert, m_key);
                m_certFile = files.first;
                m_keyFile = files.second;
                logger.debug("Saved certificate and key to temporary files");
            } catch (const std::exception& e) {
                logger.error("Failed to save certificate and key: " + std::string(e.what()));
                return false;
            }
            
            // If we have a last successful port, try that first
            std::vector<int> portsToTry = config.validPorts;
            if (m_lastSuccessfulPort > 0) {
                // Remove the last successful port from the list if it exists
                portsToTry.erase(
                    std::remove(portsToTry.begin(), portsToTry.end(), m_lastSuccessfulPort), 
                    portsToTry.end()
                );
                
                // Add it to the front of the list
                portsToTry.insert(portsToTry.begin(), m_lastSuccessfulPort);
                logger.info("Trying last successful port first: " + std::to_string(m_lastSuccessfulPort));
            }
            
            // Try each port with retries
            for (int attempt = 0; attempt < maxRetries; attempt++) {
                if (attempt > 0) {
                    logger.info("Retry attempt " + std::to_string(attempt) + " of " + std::to_string(maxRetries));
                    std::this_thread::sleep_for(std::chrono::seconds(retryDelaySeconds));
                }
                
                for (const auto& port : portsToTry) {
                    logger.header("Attempting connection on port " + std::to_string(port));
                    
                    if (m_connection.connect(m_hostname, port, m_certFile, m_keyFile)) {
                        m_port = port;
                        m_lastSuccessfulPort = port; // Remember this for next time
                        m_connected = true;
                        logger.success("Connected to " + m_hostname + " on port " + std::to_string(port));
                        return true;
                    }
                    
                    logger.warning("Failed to connect on port " + std::to_string(port));
                }
            }
            
            logger.error("Failed to connect to " + m_hostname + " on any available port after " + 
                        std::to_string(maxRetries) + " attempts");
            return false;
        }
        
        void disconnect() {
            if (m_connected) {
                m_connection.disconnect();
                m_connected = false;
            }
        }
        
        bool runProtocol() {
            if (!m_connected) {
                logger.error("Not connected, cannot run protocol");
                return false;
            }
            
            logger.header("Starting Protocol Sequence");
            
            // Protocol state
            std::string authdata;
            bool end_received = false;
            int command_count = 0;
            std::map<std::string, int> command_stats; // Track command frequencies
            auto protocol_start_time = std::chrono::high_resolution_clock::now();
            
            // Process commands until END or ERROR
            while (m_connected && !end_received) {
                // Read a line
                logger.debug("Waiting for next command...");
                std::string line;
                
                // Default timeout unless we're in POW
                int timeout = config.defaultTimeoutSeconds;
                if (!authdata.empty()) {
                    // If we've received authdata but no response yet, we're probably calculating POW
                    // Use the extended timeout
                    timeout = config.powTimeoutSeconds;
                }
                
                line = m_connection.readLine(timeout);
                
                if (line.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                // Parse the command
                auto parsed = Utils::parseCommand(line);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                logger.command("<<<", command, args);
                command_count++;
                
                // Track command statistics
                command_stats[command]++;
                
                // Process each command as per the protocol
                if (command == "ERROR") {
                    logger.error("Server sent ERROR: " + args);
                    return false;
                } else if (command == "END") {
                    logger.success("Server sent END: Protocol completed successfully");
                    // Send OK as per the pseudocode
                    logger.command(">>>", "OK", "");
                    m_connection.writeLine("OK");
                    end_received = true;
                    break;
                } else if (command == "HELO") {
                    // HELO response is EHLO according to the pseudocode
                    logger.command(">>>", "EHLO", "");
                    if (!m_connection.writeLine("EHLO")) {
                        logger.error("Failed to send EHLO response");
                        return false;
                    }
                } else if (command == "POW") {
                    // Parse POW parameters
                    std::istringstream iss(args);
                    authdata = iss.str();
                    std::string challengeStr, difficultyStr;
                    iss >> challengeStr >> difficultyStr;
                    
                    if (challengeStr.empty() || difficultyStr.empty()) {
                        logger.error("Invalid POW challenge format: " + args);
                        return false;
                    }
                    
                    int difficulty = std::stoi(difficultyStr);
                    
                    logger.info("Received POW challenge - difficulty: " + difficultyStr);
                    logger.info("Challenge: " + challengeStr);
                    
                    // Enhanced POW solving approach
                    logger.header("Starting Enhanced POW Solver");
                    logger.info("Thread count: " + std::to_string(config.powThreadCount));
                    logger.info("Batch size: " + std::to_string(config.powBatchSize));
                    logger.info("Suffix length: " + std::to_string(config.powSuffixLength));
                    
                    auto startTime = std::chrono::high_resolution_clock::now();
                    
                    // First, try with a multi-threaded approach
                    POWThreadPool powSolver(config.powThreadCount, challengeStr, difficulty);
                    std::string solution = powSolver.waitForSolution();
                    
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
                    
                    if (solution.empty()) {
                        logger.error("Failed to find POW solution");
                        return false;
                    }
                    
                    logger.success("Found POW solution in " + std::to_string(duration.count()) + " seconds");
                    
                    // Verify the solution before sending
                    std::string checkHash = Utils::sha1(challengeStr + solution);
                    std::string expectedPrefix(difficulty, '0');
                    
                    if (checkHash.compare(0, difficulty, expectedPrefix) != 0) {
                        logger.error("Solution verification failed! Hash: " + checkHash);
                        return false;
                    }
                    
                    logger.success("Solution verified. Hash: " + checkHash);
                    
                    // Send the solution
                    logger.command(">>>", solution, "");
                    if (!m_connection.writeLine(solution)) {
                        logger.error("Failed to send POW solution");
                        return false;
                    }
                } else if (command == "NAME") {
                    // Send user's name
                    std::string response = Utils::sha1(authdata + args) + " " + m_userInfo.name;
                    logger.command(">>>", "NAME", response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send NAME response");
                        return false;
                    }
                } else if (command == "MAILNUM") {
                    // Send number of email addresses
                    std::string response = Utils::sha1(authdata + args) + " " + std::to_string(m_userInfo.emails.size());
                    logger.command(">>>", "MAILNUM", response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send MAILNUM response");
                        return false;
                    }
                } else if (command.substr(0, 4) == "MAIL") {
                    // Handle MAILx commands - extract the index
                    int index = std::stoi(command.substr(4)) - 1; // 1-based to 0-based index
                    
                    if (index >= 0 && index < static_cast<int>(m_userInfo.emails.size())) {
                        std::string response = Utils::sha1(authdata + args) + " " + m_userInfo.emails[index];
                        logger.command(">>>", command, response);
                        if (!m_connection.writeLine(response)) {
                            logger.error("Failed to send " + command + " response");
                            return false;
                        }
                    } else {
                        logger.error("Invalid email index: " + command);
                        return false;
                    }
                } else if (command == "SKYPE") {
                    // Send Skype ID
                    std::string response = Utils::sha1(authdata + args) + " " + m_userInfo.skype;
                    logger.command(">>>", "SKYPE", response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send SKYPE response");
                        return false;
                    }
                } else if (command == "BIRTHDATE") {
                    // Send birthdate
                    std::string response = Utils::sha1(authdata + args) + " " + m_userInfo.birthdate;
                    logger.command(">>>", "BIRTHDATE", response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send BIRTHDATE response");
                        return false;
                    }
                } else if (command == "COUNTRY") {
                    // Send country
                    std::string response = Utils::sha1(authdata + args) + " " + m_userInfo.country;
                    logger.command(">>>", "COUNTRY", response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send COUNTRY response");
                        return false;
                    }
                } else if (command == "ADDRNUM") {
                    // Send number of address lines
                    std::string response = Utils::sha1(authdata + args) + " " + std::to_string(m_userInfo.addressLines.size());
                    logger.command(">>>", "ADDRNUM", response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send ADDRNUM response");
                        return false;
                    }
                } else if (command.substr(0, 8) == "ADDRLINE") {
                    // Handle ADDRLINEx commands - extract the index
                    int index = std::stoi(command.substr(8)) - 1; // 1-based to 0-based index
                    
                    if (index >= 0 && index < static_cast<int>(m_userInfo.addressLines.size())) {
                        std::string response = Utils::sha1(authdata + args) + " " + m_userInfo.addressLines[index];
                        logger.command(">>>", command, response);
                        if (!m_connection.writeLine(response)) {
                            logger.error("Failed to send " + command + " response");
                            return false;
                        }
                    } else {
                        logger.error("Invalid address line index: " + command);
                        return false;
                    }
                } else {
                    // Unknown command - log it and continue
                    logger.warning("Unknown command received: " + command + " " + args);
                }
            };
// Main function for running the client
int main(int argc, char* argv[]) {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }
    
    // Process command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            config.printHelp(argv[0]);
            WSACleanup(); // Clean up Winsock
            return 0;
        }
    }
    
    // Update configuration from command-line arguments
    config.updateFromArgs(argc, argv);
    
    // Print configuration
    config.printConfig();
    
    try {
        // Get user input mode (interactive or use defaults)
        bool useInteractiveMode = true;
        std::string response;
        std::cout << "Use interactive mode to enter user information? (y/n): ";
        std::getline(std::cin, response);
        if (response == "n" || response == "N") {
            useInteractiveMode = false;
        }
        
        // Set up user information
        ExatestClient::UserInfo userInfo;
        
        if (useInteractiveMode) {
            // Collect user information interactively
            userInfo = ExatestClient::UserInfo::collectFromUser();
        } else {
            // Use default information (replace with your actual information)
            userInfo.name = "Karthikeyan M";
            userInfo.emails = {"be_karthi@yahoo.co.in", "karkack@gmail.com"};
            userInfo.skype = "KarthikeyanManickavel.skype";
            userInfo.birthdate = "01.01.1990"; // Format: DD.MM.YYYY
            userInfo.country = "Germany"; // Use a valid country name
            userInfo.addressLines = {"Thirumudivakkam Road", "600132 - chennai"};
            
            // Display the default information
            std::cout << "\n" << Color::BOLD << "Using default user information:" << Color::RESET << "\n";
            std::cout << "Name: " << userInfo.name << "\n";
            std::cout << "Emails: ";
            for (size_t i = 0; i < userInfo.emails.size(); ++i) {
                std::cout << userInfo.emails[i];
                if (i < userInfo.emails.size() - 1) std::cout << ", ";
            }
            std::cout << "\n";
            std::cout << "Skype: " << userInfo.skype << "\n";
            std::cout << "Birthdate: " << userInfo.birthdate << "\n";
            std::cout << "Country: " << userInfo.country << "\n";
            std::cout << "Address: ";
            for (const auto& line : userInfo.addressLines) {
                std::cout << line << ", ";
            }
            std::cout << "\n\n";
        }
        
        // Get certificate and key
        // Certificates from the readme file (these should be configurable too)
        std::string cert = 
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBIzCBywIBATAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBleGF0ZXN0LmR5bnU\n"
            "bmV0MB4XDTI1MDQwNzEwMDQzMloXDTI1MDQyMjEwMDQzMlowIjEgMB4GA1UEAwwX\n"
            "Y2xpZW50LmV4YXRlc3QuZHludS5uZXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n"
            "AATRY2PFho4GteOgFLjK6UIWSMjzT3dP29GrW97m3O5ioByqw7WpJstDdNeVIUZQ\n"
            "OZP3VZN0W3pFmTnQjFGozliEMAoGCCqGSM49BAMCA0cAMEQCIAqmlL3y7mtbx6MS\n"
            "LgWmr59iLFo+cuAfXUyB7tei5SoeAiALcj5St2c7rUlnaS2TIe+7qhhIVD4wayeO\n"
            "DjRturJDbg==\n"
            "-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBJTCBzAIJAIHpTe1vt7jeMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEGV4YXRl\n"
            "c3QuZHludS5uZXQwHhcNMjIwNjE3MTE0MTM2WhcNMjYwNjE2MTE0MTM2WjAbMRkw\n"
            "FwYDVQQDDBBleGF0ZXN0LmR5bnUubmV0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
            "QgAEd7kDTSuNxx6xcYD1uOi89rjsMuarCIq1PnskB2Oy5QyxL/kYF9Sqc2oIfmSq\n"
            "SXMh+6sFy11s5aNcMsYoMKzewjAKBggqhkjOPQQDAgNIADBFAiEAktlnw4xaDstX\n"
            "rmu2MT01AoJqOknfvu/PRysvRj+BZkwCIGiGG312KhvHY7ajJlKet3dnZeNsga6A\n"
            "LbFlgfAzHy2a\n"
            "-----END CERTIFICATE-----\n";
        
        std::string key = 
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIO1eB3IU8m/qEpWdMShCR++gZGHTjmz7MWfnEgyrvessoAoGCCqGSM49\n"
            "AwEHoUQDQgAE0WNjxYaOBrXjoBS4yulCFkjI8093T9vRq1ve5tzuYqAcqsO1qSbL\n"
            "Q3TXlSFGUDmT91WTdFt6RZk50IxRqM5YhA==\n"
            "-----END EC PRIVATE KEY-----\n";
        
        // Ask if user wants to load certificates from files
        std::cout << "Do you want to load certificates from files? (y/n): ";
        std::getline(std::cin, response);
        if (response == "y" || response == "Y") {
            std::string certFile, keyFile;
            
            std::cout << "Enter path to certificate file: ";
            std::getline(std::cin, certFile);
            
            std::cout << "Enter path to key file: ";
            std::getline(std::cin, keyFile);
            
            // Load the files
            try {
                std::ifstream certIn(certFile);
                if (!certIn.is_open()) {
                    throw std::runtime_error("Failed to open certificate file: " + certFile);
                }
                
                std::ifstream keyIn(keyFile);
                if (!keyIn.is_open()) {
                    throw std::runtime_error("Failed to open key file: " + keyFile);
                }
                
                // Read the cert file
                cert.clear();
                std::string line;
                while (std::getline(certIn, line)) {
                    cert += line + "\n";
                }
                
                // Read the key file
                key.clear();
                while (std::getline(keyIn, line)) {
                    key += line + "\n";
                }
                
                std::cout << "Certificates loaded successfully.\n";
            } catch (const std::exception& e) {
                std::cout << Color::RED << "Error loading certificates: " << e.what() << Color::RESET << "\n";
                std::cout << "Using default certificates instead.\n";
            }
        }
        
        // Create the client
        ExatestClient client(config.serverHostname, cert, key, userInfo);
        
        logger.header("Connecting to " + config.serverHostname);
        
        // Connect with retry capability
        if (!client.connect()) {
            logger.error("Failed to establish connection to " + config.serverHostname);
            WSACleanup(); // Clean up Winsock
            return 1;
        }
        
        logger.header("Executing Protocol Sequence");
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (!client.runProtocol()) {
            logger.error("Protocol execution failed");
            client.disconnect();
            WSACleanup(); // Clean up Winsock
            return 1;
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
        
        logger.header("Protocol Sequence Completed Successfully");
        logger.success("All commands processed and END received");
        logger.success("Total execution time: " + std::to_string(total_duration) + " seconds");
        
        client.disconnect();
        
    } catch (const std::exception& e) {
        logger.error("Exception: " + std::string(e.what()));
        WSACleanup(); // Clean up Winsock
        return 1;
    } catch (...) {
        logger.error("Unknown exception occurred");
        WSACleanup(); // Clean up Winsock
        return 1;
    }
    
    // Clean up Winsock
    WSACleanup();
    
    return 0;
}
