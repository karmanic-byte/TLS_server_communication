/**
 * TLS Protocol Diagnostic Tool - Common Header
 * 
 * Shared functionality for all diagnostic tools
 */

 #ifndef TLS_DIAGNOSTIC_COMMON_H
 #define TLS_DIAGNOSTIC_COMMON_H
 
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
 #include <limits>
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
 
 // Logger class with thread safety
 class Logger {
 public:
     enum Level {
         DEBUG,
         INFO,
         WARNING,
         LEVEL_ERROR
     };
 
     Logger(Level level = INFO) : m_level(level) {}
 
     void setLevel(Level level) {
         m_level = level;
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
 
     void subHeader(const std::string& message) {
         if (m_level <= INFO) {
             std::lock_guard<std::mutex> lock(m_mutex);
             std::cout << Color::BOLD << "-- " << message << " --" 
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
 
 private:
     Level m_level;
     std::mutex m_mutex;
 };
 
 // Global logger
 extern Logger logger;
 // Define the logger in the implementation file to avoid multiple definitions
 #ifdef TLS_DIAGNOSTIC_COMMON_IMPL
 Logger logger;
 #endif
 
 // Set of valid ports to try
 const std::vector<int> VALID_PORTS = {3336, 8083, 8446, 49155, 3481, 65532};
 
 // Hostname for the Exatest server
 const std::string SERVER_HOSTNAME = "18.202.148.130";
 
 // Timeout values in seconds
 const int POW_TIMEOUT = 7200;    // 2 hours
 const int DEFAULT_TIMEOUT = 6;   // 6 seconds
 
 // Thread pool size for POW calculations
 const int POW_THREAD_COUNT = std::max(1u, std::thread::hardware_concurrency()) + 9;
 
 // The maximum number of random candidates to test per batch in POW
 const int POW_BATCH_SIZE = 1000000;
 
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
 
     // Generate random string for POW - avoiding \n\r\t and space as required
     std::string randomPowString(size_t length) {
         static const char allowed_chars[] =
             "0123456789"
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // All printable ASCII except space, tab, newline
         
         std::random_device rd;
         std::mt19937 gen(rd());
         std::uniform_int_distribution<> dist(0, sizeof(allowed_chars) - 2);
         
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
 
     // Duration formatter
     std::string formatDuration(std::chrono::milliseconds ms) {
         auto total_seconds = ms.count() / 1000;
         auto hours = total_seconds / 3600;
         auto minutes = (total_seconds % 3600) / 60;
         auto seconds = total_seconds % 60;
         auto milliseconds = ms.count() % 1000;
         
         std::stringstream ss;
         if (hours > 0) {
             ss << hours << "h ";
         }
         if (hours > 0 || minutes > 0) {
             ss << minutes << "m ";
         }
         ss << seconds << "." << std::setfill('0') << std::setw(3) << milliseconds << "s";
         
         return ss.str();
     }
     
     // Print banner
     void printBanner(const std::string& title) {
         std::cout << Color::BOLD << Color::CYAN << "\n";
         std::cout << "╔════════════════════════════════════════════════════════════╗\n";
         std::cout << "║                " << std::setw(40) << std::left << title << "║\n";
         std::cout << "╚════════════════════════════════════════════════════════════╝\n";
         std::cout << Color::RESET << std::endl;
     }
 }
 
 // POW solver result structure
 struct POWSolverResult {
     std::string solution;
     std::string hash;
     int threadId;
     std::chrono::milliseconds duration;
     uint64_t attempts;
 };
 
 // Thread pool for parallel POW computation
 class POWThreadPool {
 public:
     POWThreadPool(int numThreads, const std::string& challenge, int difficulty) 
         : m_challenge(challenge), m_difficulty(difficulty), m_targetPrefix(difficulty, '0'),
           m_running(true), m_found(false), m_totalAttempts(0) {
         
         logger.debug("Creating POW thread pool with " + std::to_string(numThreads) + 
                    " threads for difficulty " + std::to_string(difficulty));
         
         m_startTime = std::chrono::high_resolution_clock::now();
         
         // Start the worker threads
         for (int i = 0; i < numThreads; ++i) {
             m_threads.emplace_back(&POWThreadPool::workerThread, this, i);
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
     }
     
     // Wait for a solution
     POWSolverResult waitForSolution() {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_condition.wait(lock, [this] { return m_found || !m_running; });
         
         if (m_found) {
             auto endTime = std::chrono::high_resolution_clock::now();
             auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - m_startTime);
             
             POWSolverResult result;
             result.solution = m_solution;
             result.hash = m_hash;
             result.threadId = m_solutionThreadId;
             result.duration = duration;
             result.attempts = m_totalAttempts.load();
             
             return result;
         }
         
         POWSolverResult emptyResult;
         return emptyResult;
     }
 
 private:
     void workerThread(int id) {
         logger.debug("POW Worker thread " + std::to_string(id) + " started");
         
         std::random_device rd;
         std::mt19937 gen(rd() + id); // Add thread ID to seed for better distribution
         
         // Smaller suffix for faster computation and transmission
         const int suffixLength = 8; 
         
         // Local attempt counter
         uint64_t localAttempts = 0;
         
         // Tracking when to report progress
         auto lastReportTime = std::chrono::high_resolution_clock::now();
         
         while (true) {
             // Check if we should stop
             {
                 std::lock_guard<std::mutex> lock(m_mutex);
                 if (!m_running || m_found) {
                     break;
                 }
             }
             
             // Process a batch of random strings
             for (int i = 0; i < 10000; ++i) { // Process in smaller batches
                 // Generate random suffix
                 std::string suffix = Utils::randomPowString(suffixLength);
                 
                 // Compute SHA-1 hash
                 std::string hash = Utils::sha1(m_challenge + suffix);
                 
                 // Increment attempt counter
                 localAttempts++;
                 
                 // Check if hash meets the difficulty requirement
                 if (hash.compare(0, m_difficulty, m_targetPrefix) == 0) {
                     // Found a solution!
                     std::lock_guard<std::mutex> lock(m_mutex);
                     if (!m_found) {
                         m_found = true;
                         m_solution = suffix;
                         m_hash = hash;
                         m_solutionThreadId = id;
                         
                         // Add local attempts to total
                         m_totalAttempts.fetch_add(localAttempts);
                         
                         logger.success("POW Worker " + std::to_string(id) + " found solution: " + suffix);
                         logger.debug("Hash: " + hash);
                     }
                     m_condition.notify_all();
                     return;
                 }
             }
             
             // Report progress periodically
             auto now = std::chrono::high_resolution_clock::now();
             auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastReportTime);
             if (elapsed.count() >= 10) { // Report every 10 seconds
                 // Update total attempts
                 m_totalAttempts.fetch_add(localAttempts);
                 localAttempts = 0;
                 
                 // Calculate hash rate
                 auto totalElapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime);
                 double hashRate = static_cast<double>(m_totalAttempts.load()) / totalElapsed.count();
                 
                 logger.debug("Thread " + std::to_string(id) + " progress: " + 
                            std::to_string(m_totalAttempts.load()) + " attempts, " + 
                            std::to_string(hashRate) + " hashes/sec");
                 
                 lastReportTime = now;
             }
             
             // Periodically check if another thread found a solution
             {
                 std::lock_guard<std::mutex> lock(m_mutex);
                 if (m_found || !m_running) {
                     break;
                 }
             }
         }
         
         // Add remaining local attempts to total
         m_totalAttempts.fetch_add(localAttempts);
         
         logger.debug("POW Worker thread " + std::to_string(id) + " exiting");
     }
     
     std::string m_challenge;
     int m_difficulty;
     std::string m_targetPrefix;
     std::vector<std::thread> m_threads;
     std::mutex m_mutex;
     std::condition_variable m_condition;
     std::atomic<bool> m_running;
     bool m_found;
     std::string m_solution;
     std::string m_hash;
     int m_solutionThreadId;
     std::chrono::high_resolution_clock::time_point m_startTime;
     std::atomic<uint64_t> m_totalAttempts;
 };
 
 // TLS Connection class
 class TLSConnection {
 public:
     TLSConnection() : m_ssl(nullptr), m_ctx(nullptr), m_connected(false) {
         // Initialize WinSock
         WSADATA wsaData;
         if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
             logger.error("Failed to initialize Winsock");
         }
     }
     
     ~TLSConnection() {
         disconnect();
         
         // Clean up WinSock
         WSACleanup();
     }
     
     bool connect(const std::string& hostname, int port, const std::string& certFile, const std::string& keyFile) {
         auto startTime = std::chrono::high_resolution_clock::now();
         
         logger.info("Connecting to " + hostname + ":" + std::to_string(port));
         
         // Initialize SSL
         if (!initializeSSL()) {
             return false;
         }
         
         // Create a new SSL context
         m_ctx = SSL_CTX_new(TLS_client_method());
         if (!m_ctx) {
             logger.error("Failed to create SSL context");
             printSSLErrors();
             return false;
         }
         
         // Set up context options
         SSL_CTX_set_options(m_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
         SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
         
         // Load certificate and key
         if (!loadCertificates(certFile, keyFile)) {
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         // Create connection BIO
         std::string connect_str = hostname + ":" + std::to_string(port);
         BIO* bio = BIO_new_connect(connect_str.c_str());
         if (!bio) {
             logger.error("Failed to create connection BIO");
             printSSLErrors();
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         // Set non-blocking mode for connection with timeout
         BIO_set_nbio(bio, 1);
         
         // Attempt to connect
         logger.debug("Initiating TCP connection");
         
         auto connectStartTime = std::chrono::high_resolution_clock::now();
         
         if (BIO_do_connect(bio) <= 0) {
             if (!BIO_should_retry(bio)) {
                 logger.error("Connection failed immediately");
                 printSSLErrors();
                 BIO_free_all(bio);
                 SSL_CTX_free(m_ctx);
                 m_ctx = nullptr;
                 return false;
             }
             
             // Wait for connection with timeout
             int sock = -1;
             BIO_get_fd(bio, &sock);
             
             if (sock < 0) {
                 logger.error("Failed to get socket descriptor");
                 BIO_free_all(bio);
                 SSL_CTX_free(m_ctx);
                 m_ctx = nullptr;
                 return false;
             }
             
             fd_set write_fds;
             struct timeval timeout;
             timeout.tv_sec = 10;  // 10 second connection timeout
             timeout.tv_usec = 0;
             
             FD_ZERO(&write_fds);
             FD_SET(sock, &write_fds);
             
             logger.debug("Waiting for connection to complete...");
             int select_result = select(sock + 1, NULL, &write_fds, NULL, &timeout);
             
             if (select_result <= 0) {
                 if (select_result == 0) {
                     logger.error("Connection timeout");
                 } else {
                     logger.error("Select error: " + std::string(strerror(WSAGetLastError())));
                 }
                 BIO_free_all(bio);
                 SSL_CTX_free(m_ctx);
                 m_ctx = nullptr;
                 return false;
             }
             
             // Check if the connection succeeded
             int error = 0;
             int len = sizeof(error);
             if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len) < 0 || error != 0) {
                 if (error != 0) {
                     logger.error("Connection error: " + std::string(strerror(error)));
                 } else {
                     logger.error("Error getting socket option: " + std::string(strerror(WSAGetLastError())));
                 }
                 BIO_free_all(bio);
                 SSL_CTX_free(m_ctx);
                 m_ctx = nullptr;
                 return false;
             }
         }
         
         auto connectEndTime = std::chrono::high_resolution_clock::now();
         auto connectDuration = std::chrono::duration_cast<std::chrono::milliseconds>(connectEndTime - connectStartTime);
         
         logger.debug("TCP connection established in " + Utils::formatDuration(connectDuration));
         
         // Create SSL object
         m_ssl = SSL_new(m_ctx);
         if (!m_ssl) {
             logger.error("Failed to create SSL object");
             printSSLErrors();
             BIO_free_all(bio);
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         // Set hostname for SNI extension
         SSL_set_tlsext_host_name(m_ssl, hostname.c_str());
         
         // Link the BIO and SSL
         SSL_set_bio(m_ssl, bio, bio);
         
         // Set non-blocking mode
         BIO_set_nbio(bio, 1);
         
         // Perform TLS handshake with timeout
         logger.debug("Starting TLS handshake");
         
         auto handshakeStartTime = std::chrono::high_resolution_clock::now();
         
         int result;
         bool handshakeComplete = false;
         time_t startTimeT = time(NULL);
         const int handshakeTimeout = 10;  // 10 second handshake timeout
         
         while (!handshakeComplete && (time(NULL) - startTimeT) < handshakeTimeout) {
             result = SSL_connect(m_ssl);
             
             if (result == 1) {
                 handshakeComplete = true;
             } else {
                 int error = SSL_get_error(m_ssl, result);
                 
                 if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                     // Need to wait for socket to be ready
                     fd_set read_fds, write_fds;
                     FD_ZERO(&read_fds);
                     FD_ZERO(&write_fds);
                     
                     int sock = SSL_get_fd(m_ssl);
                     
                     if (error == SSL_ERROR_WANT_READ) {
                         FD_SET(sock, &read_fds);
                     } else {
                         FD_SET(sock, &write_fds);
                     }
                     
                     struct timeval timeout;
                     timeout.tv_sec = 1;  // 1 second select timeout (will retry)
                     timeout.tv_usec = 0;
                     
                     select(sock + 1, &read_fds, &write_fds, NULL, &timeout);
                     // Continue the loop and try again
                 } else {
                     logger.error("TLS handshake failed");
                     printSSLErrors();
                     SSL_free(m_ssl);
                     m_ssl = nullptr;
                     SSL_CTX_free(m_ctx);
                     m_ctx = nullptr;
                     return false;
                 }
             }
         }
         
         auto handshakeEndTime = std::chrono::high_resolution_clock::now();
         auto handshakeDuration = std::chrono::duration_cast<std::chrono::milliseconds>(handshakeEndTime - handshakeStartTime);
         
         if (!handshakeComplete) {
             logger.error("TLS handshake timed out after " + std::to_string(handshakeTimeout) + " seconds");
             SSL_free(m_ssl);
             m_ssl = nullptr;
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         logger.success("TLS handshake completed in " + Utils::formatDuration(handshakeDuration));
         logger.info("Using " + std::string(SSL_get_version(m_ssl)) + " with cipher " + 
                    std::string(SSL_get_cipher(m_ssl)));
         
         // Set socket back to blocking mode for normal operations
         int sock = SSL_get_fd(m_ssl);
         u_long iMode = 0; // 0 = blocking, 1 = non-blocking
         ioctlsocket(sock, FIONBIO, &iMode);
         
         m_connected = true;
         
         auto endTime = std::chrono::high_resolution_clock::now();
         auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
         
         logger.info("Total connection time: " + Utils::formatDuration(totalDuration));
         
         return true;
     }
     
     void disconnect() {
         if (m_ssl) {
             auto startTime = std::chrono::high_resolution_clock::now();
             
             // Try graceful shutdown
             int shutdownResult = SSL_shutdown(m_ssl);
             if (shutdownResult == 0) {
                 // Need to call again for bidirectional shutdown
                 SSL_shutdown(m_ssl);
             }
             
             SSL_free(m_ssl);
             m_ssl = nullptr;
             
             auto endTime = std::chrono::high_resolution_clock::now();
             auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
             
             logger.debug("SSL shutdown completed in " + Utils::formatDuration(duration));
         }
         
         if (m_ctx) {
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
         }
         
         m_connected = false;
         logger.info("Disconnected");
     }
     
     bool isConnected() const {
         return m_connected;
     }
     
     bool setReadTimeout(int seconds) {
         if (!m_ssl) return false;
         
         int sock = SSL_get_fd(m_ssl);
         if (sock < 0) return false;
         
         // Set socket receive timeout (Windows version)
         DWORD timeout = seconds * 1000; // convert to milliseconds
         if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
             logger.error("Failed to set read timeout: " + std::to_string(WSAGetLastError()));
             return false;
         }
         
         return true;
     }
     
     std::string readLine(int timeout_seconds = DEFAULT_TIMEOUT) {
         if (!m_ssl || !m_connected) {
             logger.error("Cannot read from closed connection");
             return "";
         }
         
         // Set socket timeout
         auto startTime = std::chrono::high_resolution_clock::now();
         setReadTimeout(timeout_seconds);
         
         std::string line;
         char buffer[1];
         int bytes_read;
         
         while (true) {
             bytes_read = SSL_read(m_ssl, buffer, 1);
             
             if (bytes_read > 0) {
                 if (buffer[0] == '\n') {
                     break;
                 }
                 line += buffer[0];
             } else {
                 int ssl_error = SSL_get_error(m_ssl, bytes_read);
                 
                 if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                     // Connection closed
                     logger.debug("Connection closed by peer while reading");
                     m_connected = false;
                     break;
                 } else if (ssl_error == SSL_ERROR_SYSCALL) {
                     // Check for timeout (WSAETIMEDOUT or WSAEWOULDBLOCK)
                     int wsaError = WSAGetLastError();
                     if (wsaError == WSAETIMEDOUT || wsaError == WSAEWOULDBLOCK) {
                         logger.error("Read timeout after " + std::to_string(timeout_seconds) + " seconds");
                     } else {
                         logger.error("Socket error during read: " + std::to_string(wsaError));
                     }
                     m_connected = false;
                     break;
                 } else {
                     logger.error("SSL read error");
                     printSSLErrors();
                     m_connected = false;
                     break;
                 }
             }
         }
         
         auto endTime = std::chrono::high_resolution_clock::now();
         auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
         
         // Ensure valid UTF-8
         std::string utf8_line = Utils::ensureUTF8(line);
         
         // If the line changed, it wasn't valid UTF-8
         if (utf8_line != line) {
             logger.warning("Received non-UTF-8 data, converted to valid UTF-8");
         }
         
         if (!line.empty()) {
             logger.debug("Read completed in " + Utils::formatDuration(duration) + 
                        ", received " + std::to_string(line.length()) + " bytes");
         }
         
         return utf8_line;
     }
     
     bool writeLine(const std::string& line) {
         if (!m_ssl || !m_connected) {
             logger.error("Cannot write to closed connection");
             return false;
         }
         
         auto startTime = std::chrono::high_resolution_clock::now();
         
         // Ensure valid UTF-8
         std::string utf8_line = Utils::ensureUTF8(line);
         
         // If the line changed, it wasn't valid UTF-8
         if (utf8_line != line) {
             logger.warning("Sending non-UTF-8 data, converted to valid UTF-8");
         }
         
         // Append newline
         std::string data = utf8_line + "\n";
         
         // Write to connection
         int bytes_written = SSL_write(m_ssl, data.c_str(), data.length());
         
         auto endTime = std::chrono::high_resolution_clock::now();
         auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
         
         if (bytes_written <= 0) {
             int ssl_error = SSL_get_error(m_ssl, bytes_written);
             
             if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                 logger.debug("Connection closed by peer while writing");
             } else {
                 logger.error("SSL write error");
                 printSSLErrors();
             }
             
             m_connected = false;
             return false;
         }
         
         logger.debug("Write completed in " + Utils::formatDuration(duration) + 
                    ", sent " + std::to_string(data.length()) + " bytes");
         
         return true;
     }
 
 private:
     SSL* m_ssl;
     SSL_CTX* m_ctx;
     bool m_connected;
     
     bool initializeSSL() {
         if (OPENSSL_init_ssl(0, NULL) != 1) {
             logger.error("Failed to initialize OpenSSL");
             printSSLErrors();
             return false;
         }
         
         logger.debug("OpenSSL initialized: " + std::string(OpenSSL_version(OPENSSL_VERSION)));
         return true;
     }
     
     bool loadCertificates(const std::string& certFile, const std::string& keyFile) {
         // Load the certificate
         if (SSL_CTX_use_certificate_file(m_ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
             logger.error("Failed to load certificate file: " + certFile);
             printSSLErrors();
             return false;
         }
         
         // Load the private key
         if (SSL_CTX_use_PrivateKey_file(m_ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
             logger.error("Failed to load private key file: " + keyFile);
             printSSLErrors();
             return false;
         }
         
         // Verify private key
         if (!SSL_CTX_check_private_key(m_ctx)) {
             logger.error("Private key does not match the certificate");
             printSSLErrors();
             return false;
         }
         
         logger.debug("Successfully loaded certificate and private key");
         return true;
     }
     
     void printSSLErrors() {
         unsigned long err;
         char err_buf[256];
         
         while ((err = ERR_get_error()) != 0) {
             ERR_error_string_n(err, err_buf, sizeof(err_buf));
             logger.error("OpenSSL error: " + std::string(err_buf));
         }
     }
 };
 
 // Configuration struct for diagnostic tools
 struct DiagnosticConfig {
     std::string hostname;
     std::string cert;
     std::string key;
     int port;
     std::string authDataVariant;
     bool delayAfterPOW;
     int delaySeconds;
     int maxCommands;
     bool verifySolutions;
     bool testMultipleConnections;
     int connectionCount;
 };
 
 // Certificate and key strings from the readme
 const std::string DEFAULT_CERT = 
     "-----BEGIN CERTIFICATE-----\n"
     "MIIBIzCBywIBATAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBleGF0ZXN0LmR5bnUu\n"
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
 
 const std::string DEFAULT_KEY = 
     "-----BEGIN EC PRIVATE KEY-----\n"
     "MHcCAQEEIO1eB3IU8m/qEpWdMShCR++gZGHTjmz7MWfnEgyrvessoAoGCCqGSM49\n"
     "AwEHoUQDQgAE0WNjxYaOBrXjoBS4yulCFkjI8093T9vRq1ve5tzuYqAcqsO1qSbL\n"
     "Q3TXlSFGUDmT91WTdFt6RZk50IxRqM5YhA==\n"
     "-----END EC PRIVATE KEY-----\n";
 
 // Function to parse common command line arguments
 DiagnosticConfig parseCommandLine(int argc, char* argv[]) {
     DiagnosticConfig config;
     
     // Set defaults
     config.hostname = SERVER_HOSTNAME;
     config.cert = DEFAULT_CERT;
     config.key = DEFAULT_KEY;
     config.port = 0; // Try all ports
     config.authDataVariant = "challenge"; // Default variant
     config.delayAfterPOW = false;
     config.delaySeconds = 10;
     config.maxCommands = 0; // No limit
     config.verifySolutions = true;
     config.testMultipleConnections = false;
     config.connectionCount = 5;
     
     for (int i = 1; i < argc; ++i) {
         std::string arg = argv[i];
         if (arg == "--host" && i + 1 < argc) {
             config.hostname = argv[++i];
         } else if (arg == "--port" && i + 1 < argc) {
             config.port = std::stoi(argv[++i]);
         } else if (arg == "--auth-variant" && i + 1 < argc) {
             config.authDataVariant = argv[++i];
         } else if (arg == "--delay-after-pow") {
             config.delayAfterPOW = true;
         } else if (arg == "--delay-seconds" && i + 1 < argc) {
             config.delaySeconds = std::stoi(argv[++i]);
         } else if (arg == "--max-commands" && i + 1 < argc) {
             config.maxCommands = std::stoi(argv[++i]);
         } else if (arg == "--no-verify") {
             config.verifySolutions = false;
         } else if (arg == "--multi-conn") {
             config.testMultipleConnections = true;
         } else if (arg == "--conn-count" && i + 1 < argc) {
             config.connectionCount = std::stoi(argv[++i]);
         } else if (arg == "--debug") {
             logger.setLevel(Logger::DEBUG);
         }
     }
     
     return config;
 }
 
 // Initialize Winsock helper
 bool initializeWinsock() {
     WSADATA wsaData;
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
         std::cerr << "Failed to initialize Winsock" << std::endl;
         return false;
     }
     return true;
 }
 
 // Cleanup Winsock helper
 void cleanupWinsock() {
     WSACleanup();
 }
 
 #endif // TLS_DIAGNOSTIC_COMMON_H