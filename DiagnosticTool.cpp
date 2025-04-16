/**
 * TLS Protocol Diagnostic Tool
 * 
 * A specialized tool for testing and analyzing the Exatest server behavior,
 * particularly focused on understanding the POW challenge mechanism.
 * 
 * Based on the Optimized TLS Protocol Client.
 * 
 * Compilation:
 * g++ -Wall -Wextra -g3 -O3 -std=c++17 tls_diagnostic_tool.cpp -o tls_diagnostic_tool.exe -lssl -lcrypto -lws2_32 -pthread
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
 
 // Logger class with thread safety
 class Logger {
 public:
     enum Level {
         DEBUG,
         INFO,
         WARNING,
         ERROR
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
 Logger logger;
 
 // Set of valid ports to try
 const std::vector<int> VALID_PORTS = {3336, 8083, 8446, 49155, 3481, 65532};
 
 // Hostname for the Exatest server
 const std::string SERVER_HOSTNAME = "18.202.148.130";
 
 // Timeout values in seconds
 const int POW_TIMEOUT = 7200;    // 2 hours
 const int DEFAULT_TIMEOUT = 6;   // 6 seconds
 
 // Thread pool size for POW calculations
 const int POW_THREAD_COUNT = std::max(1u, std::thread::hardware_concurrency());
 
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
             "000000000"
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

// Diagnostic client for protocol testing
class DiagnosticClient {
public:
    struct TestConfig {
        std::string hostname;
        std::string cert;
        std::string key;
        int testMode;
        int port;
        std::string authDataVariant;
        bool delayAfterPOW;
        int delaySeconds;
        int maxCommands;
        bool verifySolutions;
        bool testMultipleConnections;
        int connectionCount;
    };
    
    DiagnosticClient(const TestConfig& config) 
        : m_config(config), 
          m_connected(false), 
          m_port(config.port > 0 ? config.port : VALID_PORTS[1]) {
        
        // Save certificate and key to temporary files
        try {
            auto files = Utils::saveCertAndKey(m_config.cert, m_config.key);
            m_certFile = files.first;
            m_keyFile = files.second;
            logger.debug("Saved certificate and key to temporary files");
        } catch (const std::exception& e) {
            logger.error("Failed to save certificate and key: " + std::string(e.what()));
        }
    }
    
    ~DiagnosticClient() {
        disconnect();
        
        // Clean up temporary files if they exist
        if (!m_certFile.empty() && !m_keyFile.empty()) {
            Utils::cleanupTempFiles(m_certFile, m_keyFile);
        }
    }
    
    // Method to connect to the server
    bool connect() {
        if (m_config.port <= 0) {
            // Try all ports in sequence
            for (const auto& port : VALID_PORTS) {
                logger.header("Attempting connection on port " + std::to_string(port));
                
                if (m_connection.connect(m_config.hostname, port, m_certFile, m_keyFile)) {
                    m_port = port;
                    m_connected = true;
                    logger.success("Connected to " + m_config.hostname + " on port " + std::to_string(port));
                    return true;
                }
                
                logger.warning("Failed to connect on port " + std::to_string(port));
            }
            
            logger.error("Failed to connect to " + m_config.hostname + " on any available port");
            return false;
        } else {
            // Connect to the specified port
            logger.header("Connecting to port " + std::to_string(m_config.port));
            
            if (m_connection.connect(m_config.hostname, m_config.port, m_certFile, m_keyFile)) {
                m_port = m_config.port;
                m_connected = true;
                logger.success("Connected to " + m_config.hostname + " on port " + std::to_string(m_port));
                return true;
            }
            
            logger.error("Failed to connect to " + m_config.hostname + " on port " + std::to_string(m_config.port));
            return false;
        }
    }
    
    void disconnect() {
        if (m_connected) {
            m_connection.disconnect();
            m_connected = false;
        }
    }
    
    // Test POW command behavior
    bool testPOWBehavior() {
        if (!m_connected) {
            logger.error("Not connected, cannot run test");
            return false;
        }
        
        logger.header("Testing POW Behavior");
        
        // Initialize authData and other variables
        std::string authData;
        int commandsReceived = 0;
        
        // Start the protocol sequence
        while (m_connected && (m_config.maxCommands <= 0 || commandsReceived < m_config.maxCommands)) {
            // Read a line
            logger.debug("Waiting for next command...");
            std::string line;
            
            // Use the appropriate timeout
            int timeout = DEFAULT_TIMEOUT;
            if (!authData.empty()) {
                // If we're in POW mode, use the longer timeout
                timeout = POW_TIMEOUT;
            }
            
            line = m_connection.readLine(timeout);
            commandsReceived++;
            
            if (line.empty() && !m_connection.isConnected()) {
                logger.error("Connection closed by server");
                return false;
            }
            
            // Parse the command
            auto parsed = Utils::parseCommand(line);
            std::string command = parsed.first;
            std::string args = parsed.second;
            
            logger.command("<<<", command, args);
            
            // Process HELO command
            if (command == "HELO") {
                logger.info("Received HELO command");
                logger.command(">>>", "EHLO", "");
                
                auto startTime = std::chrono::high_resolution_clock::now();
                
                if (!m_connection.writeLine("EHLO")) {
                    logger.error("Failed to send EHLO response");
                    return false;
                }
                
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                
                logger.info("EHLO response sent in " + Utils::formatDuration(duration));
            }
            // Process POW command
            else if (command == "POW") {
                logger.info("Received POW command");
                
                // Parse POW parameters
                std::istringstream iss(args);
                std::string challengeStr, difficultyStr;
                iss >> challengeStr >> difficultyStr;
                
                if (challengeStr.empty() || difficultyStr.empty()) {
                    logger.error("Invalid POW challenge format: " + args);
                    return false;
                }
                
                int difficulty = std::stoi(difficultyStr);
                
                // Store the full POW line and arguments
                std::string fullPOWLine = line;
                std::string fullPOWArgs = args;
                
                // Set authData based on config
                if (m_config.authDataVariant == "full") {
                    authData = fullPOWLine;
                    logger.info("Using full POW line as authData: " + authData);
                }
                else if (m_config.authDataVariant == "args") {
                    authData = fullPOWArgs;
                    logger.info("Using POW args as authData: " + authData);
                }
                else if (m_config.authDataVariant == "challenge") {
                    authData = challengeStr;
                    logger.info("Using challenge string as authData: " + authData);
                }
                else {
                    // Default behavior
                    authData = challengeStr;
                    logger.info("Using challenge string as authData (default): " + authData);
                }
                
                // Log the challenge characteristics
                logger.info("Challenge length: " + std::to_string(challengeStr.length()) + " characters");
                logger.info("Difficulty: " + difficultyStr);
                
                // Analyze challenge string
                std::map<char, int> charCounts;
                for (char c : challengeStr) {
                    charCounts[c]++;
                }
                
                logger.info("Challenge character distribution:");
                for (const auto& pair : charCounts) {
                    logger.debug("'" + std::string(1, pair.first) + "': " + std::to_string(pair.second));
                }
                
                // Solve the POW challenge
                logger.info("Starting POW solver with " + std::to_string(POW_THREAD_COUNT) + " threads");
                
                auto startTime = std::chrono::high_resolution_clock::now();
                
                POWThreadPool powSolver(POW_THREAD_COUNT, challengeStr, difficulty);
                auto solverResult = powSolver.waitForSolution();
                
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                
                if (solverResult.solution.empty()) {
                    logger.error("Failed to find POW solution");
                    return false;
                }
                
                logger.success("Found POW solution in " + Utils::formatDuration(solverResult.duration));
                logger.info("Solution: " + solverResult.solution);
                logger.info("Hash: " + solverResult.hash);
                logger.info("Thread ID: " + std::to_string(solverResult.threadId));
                logger.info("Attempts: " + std::to_string(solverResult.attempts));
                
                double hashRate = static_cast<double>(solverResult.attempts) / (solverResult.duration.count() / 1000.0);
                logger.info("Hash rate: " + std::to_string(static_cast<uint64_t>(hashRate)) + " hashes/sec");
                
                // Optional delay after POW to see if server behavior changes
                if (m_config.delayAfterPOW) {
                    logger.info("Delaying response for " + std::to_string(m_config.delaySeconds) + " seconds");
                    std::this_thread::sleep_for(std::chrono::seconds(m_config.delaySeconds));
                }
                
                // Send the solution
                logger.command(">>>", solverResult.solution, "");
                if (!m_connection.writeLine(solverResult.solution)) {
                    logger.error("Failed to send POW solution");
                    return false;
                }
                
                // If verifying solutions, check the solution is valid
                if (m_config.verifySolutions) {
                    std::string verifyHash = Utils::sha1(challengeStr + solverResult.solution);
                    std::string reqPrefix(difficulty, '9');
                    bool valid = verifyHash.substr(0, difficulty) == reqPrefix;
                    
                    logger.info("Solution verification: " + std::string(valid ? "VALID" : "INVALID"));
                    if (!valid) {
                        logger.error("Solution hash doesn't match required prefix!");
                        logger.error("Required: " + reqPrefix);
                        logger.error("Actual: " + verifyHash.substr(0, difficulty));
                    }
                }
            }
            // Process ERROR command
            else if (command == "ERROR") {
                logger.error("Server sent ERROR: " + args);
                break;
            }
            // Process END command
            else if (command == "END") {
                logger.success("Server sent END command: " + args);
                logger.command(">>>", "OK", "");
                m_connection.writeLine("OK");
                break;
            }
            // Handle other commands by responding with authData + SHA1 checksum
            else {
                // Generate different authData variants for testing
                std::string checksumBase = authData + args;
                std::string checksum = Utils::sha1(checksumBase);
                
                logger.info("Command: " + command + ", Args: " + args);
                logger.info("Using authData: " + authData);
                logger.info("Checksum base: " + checksumBase);
                logger.info("Checksum: " + checksum);
                
                // Dummy response (don't actually send personal data in the testing tool)
                std::string response = checksum + " Test Response";
                
                logger.command(">>>", command, response);
                if (!m_connection.writeLine(response)) {
                    logger.error("Failed to send response to " + command);
                    return false;
                }
            }
        }
        
        logger.info("Test completed, commands received: " + std::to_string(commandsReceived));
        return true;
    }
    
    // Test multiple connections to analyze server behavior
    bool testMultipleConnections() {
        logger.header("Testing Multiple Connections");
        
        struct ConnectionResult {
            int port;
            std::string challenge;
            int difficulty;
            std::chrono::milliseconds connectTime;
            std::chrono::milliseconds firstCommandTime;
            std::chrono::milliseconds heloToPoWTime;
            bool success;
        };
        
        std::vector<ConnectionResult> results;
        
        for (int i = 0; i < m_config.connectionCount; i++) {
            logger.info("Connection test " + std::to_string(i+1) + " of " + 
                      std::to_string(m_config.connectionCount));
            
            // Create a new connection for each test
            TLSConnection conn;
            ConnectionResult result = {0, "", 0, std::chrono::milliseconds(0), 
                                     std::chrono::milliseconds(0), std::chrono::milliseconds(0), false};
            
            // Try each port or use the specified one
            int port = m_config.port > 0 ? m_config.port : VALID_PORTS[0];
            
            auto connectStart = std::chrono::high_resolution_clock::now();
            
            if (conn.connect(m_config.hostname, port, m_certFile, m_keyFile)) {
                auto connectEnd = std::chrono::high_resolution_clock::now();
                result.port = port;
                result.connectTime = std::chrono::duration_cast<std::chrono::milliseconds>(connectEnd - connectStart);
                
                // Wait for first command (should be HELO)
                auto firstCommandStart = std::chrono::high_resolution_clock::now();
                std::string line = conn.readLine(DEFAULT_TIMEOUT);
                auto firstCommandEnd = std::chrono::high_resolution_clock::now();
                
                result.firstCommandTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    firstCommandEnd - firstCommandStart);
                
                if (line.empty()) {
                    logger.error("No command received from server");
                    conn.disconnect();
                    results.push_back(result);
                    continue;
                }
                
                auto parsed = Utils::parseCommand(line);
                std::string command = parsed.first;
                
                if (command != "HELO") {
                    logger.error("Expected HELO command, got: " + command);
                    conn.disconnect();
                    results.push_back(result);
                    continue;
                }
                
                // Send EHLO response
                if (!conn.writeLine("EHLO")) {
                    logger.error("Failed to send EHLO response");
                    conn.disconnect();
                    results.push_back(result);
                    continue;
                }
                
                // Wait for POW command
                auto powStart = std::chrono::high_resolution_clock::now();
                line = conn.readLine(DEFAULT_TIMEOUT);
                auto powEnd = std::chrono::high_resolution_clock::now();
                
                result.heloToPoWTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    powEnd - powStart);
                
                parsed = Utils::parseCommand(line);
                command = parsed.first;
                std::string args = parsed.second;
                
                if (command != "POW") {
                    logger.error("Expected POW command, got: " + command);
                    conn.disconnect();
                    results.push_back(result);
                    continue;
                }
                
                // Parse the POW challenge and difficulty
                std::istringstream iss(args);
                iss >> result.challenge >> result.difficulty;
                
                // Don't actually solve the POW, just disconnect
                result.success = true;
                conn.disconnect();
            }
            
            results.push_back(result);
            
            // Wait a bit between connections
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // Analyze results
        logger.header("Multiple Connection Test Results");
        
        // Calculate statistics
        int successCount = 0;
        std::map<int, int> portCounts;
        std::map<int, int> difficultyCounts;
        std::set<std::string> uniqueChallenges;
        
        std::chrono::milliseconds totalConnectTime(0);
        std::chrono::milliseconds totalFirstCommandTime(0);
        std::chrono::milliseconds totalHeloToPoWTime(0);
        
        for (const auto& result : results) {
            if (result.success) {
                successCount++;
                portCounts[result.port]++;
                difficultyCounts[result.difficulty]++;
                uniqueChallenges.insert(result.challenge);
                
                totalConnectTime += result.connectTime;
                totalFirstCommandTime += result.firstCommandTime;
                totalHeloToPoWTime += result.heloToPoWTime;
            }
        }
        
        logger.info("Successful connections: " + std::to_string(successCount) + 
                  " of " + std::to_string(results.size()));
        
        if (successCount > 0) {
            // Port distribution
            logger.info("Port distribution:");
            for (const auto& pair : portCounts) {
                double percent = (static_cast<double>(pair.second) / successCount) * 100.0;
                logger.info("  Port " + std::to_string(pair.first) + ": " + 
                          std::to_string(pair.second) + " (" + 
                          std::to_string(percent) + "%)");
            }
            
            // Difficulty distribution
            logger.info("Difficulty distribution:");
            for (const auto& pair : difficultyCounts) {
                double percent = (static_cast<double>(pair.second) / successCount) * 100.0;
                logger.info("  Difficulty " + std::to_string(pair.first) + ": " + 
                          std::to_string(pair.second) + " (" + 
                          std::to_string(percent) + "%)");
            }
            
            // Challenge uniqueness
            logger.info("Unique challenges: " + std::to_string(uniqueChallenges.size()) + 
                      " of " + std::to_string(successCount));
            
            // Average timings
            double avgConnectTime = totalConnectTime.count() / static_cast<double>(successCount);
            double avgFirstCommandTime = totalFirstCommandTime.count() / static_cast<double>(successCount);
            double avgHeloToPoWTime = totalHeloToPoWTime.count() / static_cast<double>(successCount);
            
            logger.info("Average connect time: " + std::to_string(avgConnectTime) + " ms");
            logger.info("Average time to first command: " + std::to_string(avgFirstCommandTime) + " ms");
            logger.info("Average time from HELO to POW: " + std::to_string(avgHeloToPoWTime) + " ms");
        }
        
        return successCount > 0;
    }
    
    // Test different authData variants to understand what the server expects
    bool testAuthDataVariants() {
        if (!m_connected) {
            logger.error("Not connected, cannot run test");
            return false;
        }
        
        logger.header("Testing AuthData Variants");
        
        // Initialize variables
        std::string powLine;
        std::string powCommand;
        std::string powArgs;
        std::string challenge;
        std::string difficulty;
        
        // Capture the POW command
        while (m_connected) {
            // Read a line
            logger.debug("Waiting for command...");
            std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
            
            if (line.empty() && !m_connection.isConnected()) {
                logger.error("Connection closed by server");
                return false;
            }
            
            // Parse the command
            auto parsed = Utils::parseCommand(line);
            std::string command = parsed.first;
            std::string args = parsed.second;
            
            logger.command("<<<", command, args);
            
            if (command == "HELO") {
                logger.command(">>>", "EHLO", "");
                if (!m_connection.writeLine("EHLO")) {
                    logger.error("Failed to send EHLO response");
                    return false;
                }
            }
            else if (command == "POW") {
                // Store the POW details
                powLine = line;
                powCommand = command;
                powArgs = args;
                
                std::istringstream iss(args);
                iss >> challenge >> difficulty;
                
                // Solve the POW
                logger.info("Solving POW challenge...");
                int diff = std::stoi(difficulty);
                
                POWThreadPool powSolver(POW_THREAD_COUNT, challenge, diff);
                auto solverResult = powSolver.waitForSolution();
                
                if (solverResult.solution.empty()) {
                    logger.error("Failed to find POW solution");
                    return false;
                }
                
                logger.info("Found POW solution: " + solverResult.solution);
                logger.command(">>>", solverResult.solution, "");
                if (!m_connection.writeLine(solverResult.solution)) {
                    logger.error("Failed to send POW solution");
                    return false;
                }
                
                break;
            }
            else if (command == "ERROR") {
                logger.error("Server sent ERROR: " + args);
                return false;
            }
        }
        
        // Now test different authData variants with the next command
        std::vector<std::pair<std::string, std::string>> variants = {
            {"full", powLine},
            {"command", powCommand},
            {"args", powArgs},
            {"challenge", challenge},
            {"challenge+difficulty", challenge + " " + difficulty},
        };
        
        // Wait for the next command to test variants
        std::string nextCommandLine = m_connection.readLine(DEFAULT_TIMEOUT);
        if (nextCommandLine.empty() && !m_connection.isConnected()) {
            logger.error("Connection closed by server");
            return false;
        }
        
        auto parsed = Utils::parseCommand(nextCommandLine);
        std::string nextCommand = parsed.first;
        std::string nextArgs = parsed.second;
        
        logger.command("<<<", nextCommand, nextArgs);
        
        // Test each variant by computing different checksums
        logger.info("Testing authData variants for command: " + nextCommand + " " + nextArgs);
        
        for (const auto& variant : variants) {
            std::string variantName = variant.first;
            std::string authData = variant.second;
            
            std::string checksumBase = authData + nextArgs;
            std::string checksum = Utils::sha1(checksumBase);
            
            logger.info("Variant: " + variantName);
            logger.info("  AuthData: " + authData);
            logger.info("  Checksum base: " + checksumBase);
            logger.info("  Checksum: " + checksum);
        }
        
        // Respond with the authData variant specified in the config
        std::string authData;
        if (m_config.authDataVariant == "full") {
            authData = powLine;
        }
        else if (m_config.authDataVariant == "command") {
            authData = powCommand;
        }
        else if (m_config.authDataVariant == "args") {
            authData = powArgs;
        }
        else if (m_config.authDataVariant == "challenge") {
            authData = challenge;
        }
        else if (m_config.authDataVariant == "challenge+difficulty") {
            authData = challenge + " " + difficulty;
        }
        else {
            // Default
            authData = challenge;
        }
        
        std::string checksum = Utils::sha1(authData + nextArgs);
        std::string response = checksum + " Test Response";
        
        logger.info("Responding with variant: " + m_config.authDataVariant);
        logger.command(">>>", nextCommand, response);
        
        if (!m_connection.writeLine(response)) {
            logger.error("Failed to send response with variant: " + m_config.authDataVariant);
            return false;
        }
        
        // Wait for server response
        std::string serverResponse = m_connection.readLine(DEFAULT_TIMEOUT);
        if (serverResponse.empty() && !m_connection.isConnected()) {
            logger.error("Connection closed by server");
            return false;
        }
        
        parsed = Utils::parseCommand(serverResponse);
        std::string responseCommand = parsed.first;
        std::string responseArgs = parsed.second;
        
        logger.command("<<<", responseCommand, responseArgs);
        
        if (responseCommand == "ERROR") {
            logger.error("Server rejected variant '" + m_config.authDataVariant + "': " + responseArgs);
            return false;
        }
        
        logger.success("Server accepted variant: " + m_config.authDataVariant);
        return true;
    }
    
    // Test solving POW with different solutions
    bool testPOWSolutions() {
        if (!m_connected) {
            logger.error("Not connected, cannot run test");
            return false;
        }
        
        logger.header("Testing POW Solutions");
        
        // Initialize variables
        std::/**
 * TLS Protocol Diagnostic Tool
 * 
 * A specialized tool for testing and analyzing the Exatest server behavior,
 * particularly focused on understanding the POW challenge mechanism.
 * 
 * Based on the Optimized TLS Protocol Client.
 * 
 * Compilation:
 * g++ -Wall -Wextra -g3 -O3 -std=c++17 tls_diagnostic_tool.cpp -o tls_diagnostic_tool.exe -lssl -lcrypto -lws2_32 -pthread
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

// Logger class with thread safety
class Logger {
public:
    enum Level {
        DEBUG,
        INFO,
        WARNING,
        ERROR
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
Logger logger;

// Set of valid ports to try
const std::vector<int> VALID_PORTS = {3336, 8083, 8446, 49155, 3481, 65532};

// Hostname for the Exatest server
const std::string SERVER_HOSTNAME = "18.202.148.130";

// Timeout values in seconds
const int POW_TIMEOUT = 7200;    // 2 hours
const int DEFAULT_TIMEOUT = 6;   // 6 seconds

// Thread pool size for POW calculations
const int POW_THREAD_COUNT = std::max(1u, std::thread::hardware_concurrency());

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
            logger.header("Testing POW Solutions");
        
            // Initialize variables
            std::string challenge;
            int difficulty = 0;
            
            // Get to the POW challenge
            while (m_connected) {
                std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                
                if (line.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                auto parsed = Utils::parseCommand(line);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                logger.command("<<<", command, args);
                
                if (command == "HELO") {
                    logger.command(">>>", "EHLO", "");
                    if (!m_connection.writeLine("EHLO")) {
                        logger.error("Failed to send EHLO response");
                        return false;
                    }
                }
                else if (command == "POW") {
                    std::istringstream iss(args);
                    iss >> challenge >> difficulty;
                    
                    logger.info("Received POW challenge: " + challenge);
                    logger.info("Difficulty: " + std::to_string(difficulty));
                    break;
                }
                else if (command == "ERROR") {
                    logger.error("Server sent ERROR: " + args);
                    return false;
                }
            }
            
            if (challenge.empty() || difficulty == 0) {
                logger.error("Did not receive a valid POW challenge");
                return false;
            }
            
            // Generate and test multiple solutions
            logger.info("Generating multiple valid solutions...");
            
            std::vector<std::string> solutions;
            std::vector<std::string> hashes;
            
            // Solve with multiple threads to find different solutions
            for (int i = 0; i < 3; i++) {
                logger.info("Finding solution #" + std::to_string(i+1));
                
                POWThreadPool powSolver(POW_THREAD_COUNT, challenge, difficulty);
                auto solverResult = powSolver.waitForSolution();
                
                if (solverResult.solution.empty()) {
                    logger.error("Failed to find POW solution");
                    continue;
                }
                
                logger.success("Found solution #" + std::to_string(i+1) + ": " + solverResult.solution);
                logger.info("Hash: " + solverResult.hash);
                
                solutions.push_back(solverResult.solution);
                hashes.push_back(solverResult.hash);
                
                // If this is not the last solution, reconnect for the next test
                if (i < 2) {
                    disconnect();
                    if (!connect()) {
                        logger.error("Failed to reconnect for next solution test");
                        return false;
                    }
                    
                    // Skip back to the POW challenge
                    bool foundPOW = false;
                    while (m_connected && !foundPOW) {
                        std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                        
                        if (line.empty() && !m_connection.isConnected()) {
                            logger.error("Connection closed by server");
                            return false;
                        }
                        
                        auto parsed = Utils::parseCommand(line);
                        std::string command = parsed.first;
                        std::string args = parsed.second;
                        
                        logger.command("<<<", command, args);
                        
                        if (command == "HELO") {
                            logger.command(">>>", "EHLO", "");
                            if (!m_connection.writeLine("EHLO")) {
                                logger.error("Failed to send EHLO response");
                                return false;
                            }
                        }
                        else if (command == "POW") {
                            std::string newChallenge;
                            int newDifficulty;
                            std::istringstream iss(args);
                            iss >> newChallenge >> newDifficulty;
                            
                            if (newChallenge != challenge || newDifficulty != difficulty) {
                                logger.warning("Got different POW challenge on reconnect!");
                                logger.warning("Old: " + challenge + " " + std::to_string(difficulty));
                                logger.warning("New: " + newChallenge + " " + std::to_string(newDifficulty));
                                challenge = newChallenge;
                                difficulty = newDifficulty;
                            }
                            
                            foundPOW = true;
                        }
                        else if (command == "ERROR") {
                            logger.error("Server sent ERROR: " + args);
                            return false;
                        }
                    }
                }
            }
            
            // Test the solutions
            logger.info("Testing solutions against server...");
            
            for (size_t i = 0; i < solutions.size(); i++) {
                logger.info("Testing solution #" + std::to_string(i+1) + ": " + solutions[i]);
                
                // Send the solution
                logger.command(">>>", solutions[i], "");
                if (!m_connection.writeLine(solutions[i])) {
                    logger.error("Failed to send solution");
                    return false;
                }
                
                // Wait for response
                std::string response = m_connection.readLine(DEFAULT_TIMEOUT);
                if (response.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                auto parsed = Utils::parseCommand(response);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                logger.command("<<<", command, args);
                
                if (command == "ERROR") {
                    logger.error("Server rejected solution #" + std::to_string(i+1) + ": " + args);
                } else {
                    logger.success("Server accepted solution #" + std::to_string(i+1));
                    // We received the next command, just disconnect and proceed
                    break;
                }
                
                // If not the last solution, reconnect for the next test
                if (i < solutions.size() - 1) {
                    disconnect();
                    if (!connect()) {
                        logger.error("Failed to reconnect for next solution test");
                        return false;
                    }
                    
                    // Skip back to the POW challenge
                    bool foundPOW = false;
                    while (m_connected && !foundPOW) {
                        std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                        
                        if (line.empty() && !m_connection.isConnected()) {
                            logger.error("Connection closed by server");
                            return false;
                        }
                        
                        auto parsed = Utils::parseCommand(line);
                        std::string command = parsed.first;
                        std::string args = parsed.second;
                        
                        logger.command("<<<", command, args);
                        
                        if (command == "HELO") {
                            logger.command(">>>", "EHLO", "");
                            if (!m_connection.writeLine("EHLO")) {
                                logger.error("Failed to send EHLO response");
                                return false;
                            }
                        }
                        else if (command == "POW") {
                            foundPOW = true;
                        }
                        else if (command == "ERROR") {
                            logger.error("Server sent ERROR: " + args);
                            return false;
                        }
                    }
                }
            }
            
            logger.success("Completed POW solution testing");
            return true;
        }
        
        // Test for POW timeout behavior
        bool testPOWTimeout() {
            if (!m_connected) {
                logger.error("Not connected, cannot run test");
                return false;
            }
            
            logger.header("Testing POW Timeout Behavior");
            
            // Initialize variables
            std::string challenge;
            int difficulty = 0;
            
            // Get to the POW challenge
            while (m_connected) {
                std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                
                if (line.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                auto parsed = Utils::parseCommand(line);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                logger.command("<<<", command, args);
                
                if (command == "HELO") {
                    logger.command(">>>", "EHLO", "");
                    if (!m_connection.writeLine("EHLO")) {
                        logger.error("Failed to send EHLO response");
                        return false;
                    }
                }
                else if (command == "POW") {
                    std::istringstream iss(args);
                    iss >> challenge >> difficulty;
                    
                    logger.info("Received POW challenge: " + challenge);
                    logger.info("Difficulty: " + std::to_string(difficulty));
                    break;
                }
                else if (command == "ERROR") {
                    logger.error("Server sent ERROR: " + args);
                    return false;
                }
            }
            
            if (challenge.empty() || difficulty == 0) {
                logger.error("Did not receive a valid POW challenge");
                return false;
            }
            
            // Wait for a timeout (but less than the full 2 hours)
            int waitTime = 60; // 1 minute for testing, adjust as needed
            logger.info("Waiting " + std::to_string(waitTime) + " seconds to test partial timeout behavior...");
            
            std::this_thread::sleep_for(std::chrono::seconds(waitTime));
            
            // Check if server is still responsive
            logger.info("Testing if server is still responsive after " + std::to_string(waitTime) + " seconds");
            
            // Send an invalid solution intentionally
            std::string invalidSolution = "INVALID_SOLUTION";
            logger.command(">>>", invalidSolution, "");
            
            if (!m_connection.writeLine(invalidSolution)) {
                logger.error("Failed to send invalid solution");
                return false;
            }
            
            // Wait for response
            std::string response = m_connection.readLine(DEFAULT_TIMEOUT);
            if (response.empty() && !m_connection.isConnected()) {
                logger.error("Connection closed by server after " + std::to_string(waitTime) + " seconds");
                return false;
            }
            
            auto parsed = Utils::parseCommand(response);
            std::string command = parsed.first;
            std::string args = parsed.second;
            
            logger.command("<<<", command, args);
            
            if (command == "ERROR") {
                logger.success("Server still responsive after " + std::to_string(waitTime) + 
                             " seconds, rejected invalid solution: " + args);
            } else {
                logger.warning("Unexpected response from server after " + std::to_string(waitTime) + 
                             " seconds: " + command + " " + args);
            }
            
            return true;
        }
        
        // Test response timing for various commands
        bool testResponseTiming() {
            if (!m_connected) {
                logger.error("Not connected, cannot run test");
                return false;
            }
            
            logger.header("Testing Server Response Timing");
            
            // Maps to store timing data
            std::map<std::string, std::vector<std::chrono::milliseconds>> commandReceiveTimes;
            std::map<std::string, std::vector<std::chrono::milliseconds>> commandRespondTimes;
            
            // Initialize variables
            std::string authData;
            bool isFirstCommand = true;
            bool powSolved = false;
            
            // Process commands and time responses
            while (m_connected) {
                // Read a line
                logger.debug("Waiting for next command...");
                std::string line;
                
                auto receiveStart = std::chrono::high_resolution_clock::now();
                
                // Use the appropriate timeout
                int timeout = powSolved ? POW_TIMEOUT : DEFAULT_TIMEOUT;
                line = m_connection.readLine(timeout);
                
                auto receiveEnd = std::chrono::high_resolution_clock::now();
                auto receiveDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    receiveEnd - receiveStart);
                
                if (line.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    break;
                }
                
                // Parse the command
                auto parsed = Utils::parseCommand(line);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                // Record receive time
                commandReceiveTimes[command].push_back(receiveDuration);
                
                logger.command("<<<", command, args);
                logger.info("Received " + command + " in " + Utils::formatDuration(receiveDuration));
                
                // Process the command
                if (command == "ERROR") {
                    logger.error("Server sent ERROR: " + args);
                    break;
                } else if (command == "END") {
                    logger.success("Server sent END: Protocol completed successfully");
                    
                    auto respondStart = std::chrono::high_resolution_clock::now();
                    
                    logger.command(">>>", "OK", "");
                    if (!m_connection.writeLine("OK")) {
                        logger.error("Failed to send OK response");
                        break;
                    }
                    
                    auto respondEnd = std::chrono::high_resolution_clock::now();
                    auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        respondEnd - respondStart);
                    
                    commandRespondTimes[command].push_back(respondDuration);
                    logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                    
                    break;
                } else if (command == "HELO") {
                    auto respondStart = std::chrono::high_resolution_clock::now();
                    
                    logger.command(">>>", "EHLO", "");
                    if (!m_connection.writeLine("EHLO")) {
                        logger.error("Failed to send EHLO response");
                        break;
                    }
                    
                    auto respondEnd = std::chrono::high_resolution_clock::now();
                    auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        respondEnd - respondStart);
                    
                    commandRespondTimes[command].push_back(respondDuration);
                    logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                    
                    isFirstCommand = false;
                } else if (command == "POW") {
                    std::istringstream iss(args);
                    std::string challengeStr, difficultyStr;
                    iss >> challengeStr >> difficultyStr;
                    
                    if (challengeStr.empty() || difficultyStr.empty()) {
                        logger.error("Invalid POW challenge format: " + args);
                        break;
                    }
                    
                    int difficulty = std::stoi(difficultyStr);
                    
                    // Set up authData for future commands
                    authData = challengeStr;
                    
                    // Solve the POW challenge
                    logger.info("Solving POW challenge...");
                    
                    auto respondStart = std::chrono::high_resolution_clock::now();
                    
                    // Create a dummy solution that's just the first 'difficulty' chars from the challenge
                    // Not a valid solution, but we just want to test timing
                    std::string dummySolution = challengeStr.substr(0, std::min(8, static_cast<int>(challengeStr.length())));
                    
                    logger.command(">>>", dummySolution, "");
                    if (!m_connection.writeLine(dummySolution)) {
                        logger.error("Failed to send dummy POW solution");
                        break;
                    }
                    
                    auto respondEnd = std::chrono::high_resolution_clock::now();
                    auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        respondEnd - respondStart);
                    
                    commandRespondTimes[command].push_back(respondDuration);
                    logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                    
                    powSolved = true;
                } else {
                    // Handle other commands by responding quickly with a dummy response
                    auto respondStart = std::chrono::high_resolution_clock::now();
                    
                    // Generate a dummy response with valid checksum
                    std::string checksum = Utils::sha1(authData + args);
                    std::string response = checksum + " DummyResponse";
                    
                    logger.command(">>>", command, response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send response to " + command);
                        break;
                    }
                    
                    auto respondEnd = std::chrono::high_resolution_clock::now();
                    auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        respondEnd - respondStart);
                    
                    commandRespondTimes[command].push_back(respondDuration);
                    logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                }
            }
            
            // Analyze timing results
            logger.header("Server Response Timing Analysis");
            
            // Calculate averages for receive times
            logger.info("Command Receive Timing (server -> client):");
            for (const auto& pair : commandReceiveTimes) {
                double avgTime = 0.0;
                double minTime = std::numeric_limits<double>::max();
                double maxTime = 0.0;
                
                for (const auto& time : pair.second) {
                    double ms = time.count();
                    avgTime += ms;
                    minTime = std::min(minTime, ms);
                    maxTime = std::max(maxTime, ms);
                }
                
                avgTime /= pair.second.size();
                
                logger.info("  " + pair.first + ": " + 
                          "Avg: " + std::to_string(avgTime) + " ms, " +
                          "Min: " + std::to_string(minTime) + " ms, " +
                          "Max: " + std::to_string(maxTime) + " ms, " +
                          "Count: " + std::to_string(pair.second.size()));
            }
            
            // Calculate averages for respond times
            logger.info("Response Processing Timing (client -> server):");
            for (const auto& pair : commandRespondTimes) {
                double avgTime = 0.0;
                double minTime = std::numeric_limits<double>::max();
                double maxTime = 0.0;
                
                for (const auto& time : pair.second) {
                    double ms = time.count();
                    avgTime += ms;
                    minTime = std::min(minTime, ms);
                    maxTime = std::max(maxTime, ms);
                }
                
                avgTime /= pair.second.size();
                
                logger.info("  " + pair.first + ": " + 
                          "Avg: " + std::to_string(avgTime) + " ms, " +
                          "Min: " + std::to_string(minTime) + " ms, " +
                          "Max: " + std::to_string(maxTime) + " ms, " +
                          "Count: " + std::to_string(pair.second.size()));
            }
            
            return true;
        }
        
        bool isConnected() const {
            return m_connected && m_connection.isConnected();
        }
        
        int getPort() const {
            return m_port;
        }
    
    private:
        TestConfig m_config;
        std::string m_certFile;
        std::string m_keyFile;
        TLSConnection m_connection;
        bool m_connected;
        int m_port;
    };
    
    int main(int argc, char* argv[]) {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Failed to initialize Winsock" << std::endl;
            return 1;
        }
        
        // Process command-line arguments
        DiagnosticClient::TestConfig config;
        config.hostname = SERVER_HOSTNAME;
        config.testMode = 0; // Default test mode (POW behavior)
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
            } else if (arg == "--mode" && i + 1 < argc) {
                config.testMode = std::stoi(argv[++i]);
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
            } else if (arg == "--help") {
                std::cout << "TLS Protocol Diagnostic Tool" << std::endl;
                std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
                std::cout << "Options:" << std::endl;
                std::cout << "  --host HOSTNAME     Target hostname (default: " << SERVER_HOSTNAME << ")" << std::endl;
                std::cout << "  --mode MODE         Test mode (default: 0)" << std::endl;
                std::cout << "                        0: Test POW behavior" << std::endl;
                std::cout << "                        1: Test multiple connections" << std::endl;
                std::cout << "                        2: Test authData variants" << std::endl;
                std::cout << "                        3: Test POW solutions" << std::endl;
                std::cout << "                        4: Test POW timeout" << std::endl;
                std::cout << "                        5: Test response timing" << std::endl;
                std::cout << "  --port PORT         Use specific port (default: try all)" << std::endl;
                std::cout << "  --auth-variant VAR  AuthData variant to use (default: challenge)" << std::endl;
                std::cout << "                        challenge: Use challenge string" << std::endl;
                std::cout << "                        args: Use full POW args" << std::endl;
                std::cout << "                        full: Use full POW line" << std::endl;
                std::cout << "  --delay-after-pow   Delay after solving POW before sending solution" << std::endl;
                std::cout << "  --delay-seconds N   Seconds to delay (default: 10)" << std::endl;
                std::cout << "  --max-commands N    Maximum commands to process (default: no limit)" << std::endl;
                std::cout << "  --no-verify         Disable solution verification" << std::endl;
                std::cout << "  --multi-conn        Test multiple connections" << std::endl;
                std::cout << "  --conn-count N      Number of connections to test (default: 5)" << std::endl;
                std::cout << "  --debug             Enable debug logging" << std::endl;
                std::cout << "  --help              Display this help message" << std::endl;
                WSACleanup(); // Clean up Winsock
                return 0;
            }
        }
        
        // Load certificate and key from embedded strings
        config.cert = 
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
        
        config.key = 
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIO1eB3IU8m/qEpWdMShCR++gZGHTjmz7MWfnEgyrvessoAoGCCqGSM49\n"
            "AwEHoUQDQgAE0WNjxYaOBrXjoBS4yulCFkjI8093T9vRq1ve5tzuYqAcqsO1qSbL\n"
            "Q3TXlSFGUDmT91WTdFt6RZk50IxRqM5YhA==\n"
            "-----END EC PRIVATE KEY-----\n";
        
        std::cout << Color::BOLD << Color::CYAN << "\n";
        std::cout << "╔════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                TLS Protocol Diagnostic Tool                ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════╝\n";
        std::cout << Color::RESET << std::endl;
        
        std::cout << "Target host: " << Color::BOLD << config.hostname << Color::RESET << std::endl;
        std::cout << "Test mode: " << Color::BOLD << config.testMode << Color::RESET << std::endl;
        if (config.port > 0) {
            std::cout << "Port: " << Color::BOLD << config.port << Color::RESET << std::endl;
        } else {
            std::cout << "Ports: " << Color::BOLD << "Auto (try all)" << Color::RESET << std::endl;
        }
        std::cout << "AuthData variant: " << Color::BOLD << config.authDataVariant << Color::RESET << std::endl;
        std::cout << "POW threads: " << Color::BOLD << POW_THREAD_COUNT << Color::RESET << std::endl;
        std::cout << std::endl;
        
        try {
            DiagnosticClient client(config);
            
            bool result = false;
            
            // For modes that don't need a connection first, handle them separately
            if (config.testMode == 1 && config.testMultipleConnections) {
                logger.header("Testing Multiple Connections");
                result = client.testMultipleConnections();
            } else {
                // For all other modes, connect first
                logger.header("Connecting to " + config.hostname);
                
                if (!client.connect()) {
                    logger.error("Failed to establish connection to " + config.hostname);
                    WSACleanup(); // Clean up Winsock
                    return 1;
                }
                
                // Run the appropriate test based on mode
                switch (config.testMode) {
                    case 0:
                        // Test POW behavior
                        result = client.testPOWBehavior();
                        break;
                    case 2:
                        // Test authData variants
                        result = client.testAuthDataVariants();
                        break;
                    case 3:
                        // Test POW solutions
                        result = client.testPOWSolutions();
                        break;
                    case 4:
                        // Test POW timeout
                        result = client.testPOWTimeout();
                        break;
                    case 5:
                        // Test response timing
                        result = client.testResponseTiming();
                        break;
                    default:
                        logger.error("Unknown test mode: " + std::to_string(config.testMode));
                        result = false;
                        break;
                }
                
                client.disconnect();
            }
            
            if (        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
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
    
    // Diagnostic client for protocol testing
    class DiagnosticClient {
    public:
        struct TestConfig {
            std::string hostname;
            std::string cert;
            std::string key;
            int testMode;
            int port;
            std::string authDataVariant;
            bool delayAfterPOW;
            int delaySeconds;
            int maxCommands;
            bool verifySolutions;
            bool testMultipleConnections;
            int connectionCount;
        };
        
        DiagnosticClient(const TestConfig& config) 
            : m_config(config), 
              m_connected(false), 
              m_port(config.port > 0 ? config.port : VALID_PORTS[0]) {
            
            // Save certificate and key to temporary files
            try {
                auto files = Utils::saveCertAndKey(m_config.cert, m_config.key);
                m_certFile = files.first;
                m_keyFile = files.second;
                logger.debug("Saved certificate and key to temporary files");
            } catch (const std::exception& e) {
                logger.error("Failed to save certificate and key: " + std::string(e.what()));
            }
        }
        
        ~DiagnosticClient() {
            disconnect();
            
            // Clean up temporary files if they exist
            if (!m_certFile.empty() && !m_keyFile.empty()) {
                Utils::cleanupTempFiles(m_certFile, m_keyFile);
            }
        }
        
        // Method to connect to the server
        bool connect() {
            if (m_config.port <= 0) {
                // Try all ports in sequence
                for (const auto& port : VALID_PORTS) {
                    logger.header("Attempting connection on port " + std::to_string(port));
                    
                    if (m_connection.connect(m_config.hostname, port, m_certFile, m_keyFile)) {
                        m_port = port;
                        m_connected = true;
                        logger.success("Connected to " + m_config.hostname + " on port " + std::to_string(port));
                        return true;
                    }
                    
                    logger.warning("Failed to connect on port " + std::to_string(port));
                }
                
                logger.error("Failed to connect to " + m_config.hostname + " on any available port");
                return false;
            } else {
                // Connect to the specified port
                logger.header("Connecting to port " + std::to_string(m_config.port));
                
                if (m_connection.connect(m_config.hostname, m_config.port, m_certFile, m_keyFile)) {
                    m_port = m_config.port;
                    m_connected = true;
                    logger.success("Connected to " + m_config.hostname + " on port " + std::to_string(m_port));
                    return true;
                }
                
                logger.error("Failed to connect to " + m_config.hostname + " on port " + std::to_string(m_config.port));
                return false;
            }
        }
        
        void disconnect() {
            if (m_connected) {
                m_connection.disconnect();
                m_connected = false;
            }
        }
        
        // Test POW command behavior
        bool testPOWBehavior() {
            if (!m_connected) {
                logger.error("Not connected, cannot run test");
                return false;
            }
            
            logger.header("Testing POW Behavior");
            
            // Initialize authData and other variables
            std::string authData;
            int commandsReceived = 0;
            
            // Start the protocol sequence
            while (m_connected && (m_config.maxCommands <= 0 || commandsReceived < m_config.maxCommands)) {
                // Read a line
                logger.debug("Waiting for next command...");
                std::string line;
                
                // Use the appropriate timeout
                int timeout = DEFAULT_TIMEOUT;
                if (!authData.empty()) {
                    // If we're in POW mode, use the longer timeout
                    timeout = POW_TIMEOUT;
                }
                
                line = m_connection.readLine(timeout);
                commandsReceived++;
                
                if (line.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                // Parse the command
                auto parsed = Utils::parseCommand(line);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                logger.command("<<<", command, args);
                
                // Process HELO command
                if (command == "HELO") {
                    logger.info("Received HELO command");
                    logger.command(">>>", "EHLO", "");
                    
                    auto startTime = std::chrono::high_resolution_clock::now();
                    
                    if (!m_connection.writeLine("EHLO")) {
                        logger.error("Failed to send EHLO response");
                        return false;
                    }
                    
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                    
                    logger.info("EHLO response sent in " + Utils::formatDuration(duration));
                }
                // Process POW command
                else if (command == "POW") {
                    logger.info("Received POW command");
                    
                    // Parse POW parameters
                    std::istringstream iss(args);
                    std::string challengeStr, difficultyStr;
                    iss >> challengeStr >> difficultyStr;
                    
                    if (challengeStr.empty() || difficultyStr.empty()) {
                        logger.error("Invalid POW challenge format: " + args);
                        return false;
                    }
                    
                    int difficulty = std::stoi(difficultyStr);
                    
                    // Store the full POW line and arguments
                    std::string fullPOWLine = line;
                    std::string fullPOWArgs = args;
                    
                    // Set authData based on config
                    if (m_config.authDataVariant == "full") {
                        authData = fullPOWLine;
                        logger.info("Using full POW line as authData: " + authData);
                    }
                    else if (m_config.authDataVariant == "args") {
                        authData = fullPOWArgs;
                        logger.info("Using POW args as authData: " + authData);
                    }
                    else if (m_config.authDataVariant == "challenge") {
                        authData = challengeStr;
                        logger.info("Using challenge string as authData: " + authData);
                    }
                    else {
                        // Default behavior
                        authData = challengeStr;
                        logger.info("Using challenge string as authData (default): " + authData);
                    }
                    
                    // Log the challenge characteristics
                    logger.info("Challenge length: " + std::to_string(challengeStr.length()) + " characters");
                    logger.info("Difficulty: " + difficultyStr);
                    
                    // Analyze challenge string
                    std::map<char, int> charCounts;
                    for (char c : challengeStr) {
                        charCounts[c]++;
                    }
                    
                    logger.info("Challenge character distribution:");
                    for (const auto& pair : charCounts) {
                        logger.debug("'" + std::string(1, pair.first) + "': " + std::to_string(pair.second));
                    }
                    
                    // Solve the POW challenge
                    logger.info("Starting POW solver with " + std::to_string(POW_THREAD_COUNT) + " threads");
                    
                    auto startTime = std::chrono::high_resolution_clock::now();
                    
                    POWThreadPool powSolver(POW_THREAD_COUNT, challengeStr, difficulty);
                    auto solverResult = powSolver.waitForSolution();
                    
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                    
                    if (solverResult.solution.empty()) {
                        logger.error("Failed to find POW solution");
                        return false;
                    }
                    
                    logger.success("Found POW solution in " + Utils::formatDuration(solverResult.duration));
                    logger.info("Solution: " + solverResult.solution);
                    logger.info("Hash: " + solverResult.hash);
                    logger.info("Thread ID: " + std::to_string(solverResult.threadId));
                    logger.info("Attempts: " + std::to_string(solverResult.attempts));
                    
                    double hashRate = static_cast<double>(solverResult.attempts) / (solverResult.duration.count() / 1000.0);
                    logger.info("Hash rate: " + std::to_string(static_cast<uint64_t>(hashRate)) + " hashes/sec");
                    
                    // Optional delay after POW to see if server behavior changes
                    if (m_config.delayAfterPOW) {
                        logger.info("Delaying response for " + std::to_string(m_config.delaySeconds) + " seconds");
                        std::this_thread::sleep_for(std::chrono::seconds(m_config.delaySeconds));
                    }
                    
                    // Send the solution
                    logger.command(">>>", solverResult.solution, "");
                    if (!m_connection.writeLine(solverResult.solution)) {
                        logger.error("Failed to send POW solution");
                        return false;
                    }
                    
                    // If verifying solutions, check the solution is valid
                    if (m_config.verifySolutions) {
                        std::string verifyHash = Utils::sha1(challengeStr + solverResult.solution);
                        std::string reqPrefix(difficulty, '0');
                        bool valid = verifyHash.substr(0, difficulty) == reqPrefix;
                        
                        logger.info("Solution verification: " + std::string(valid ? "VALID" : "INVALID"));
                        if (!valid) {
                            logger.error("Solution hash doesn't match required prefix!");
                            logger.error("Required: " + reqPrefix);
                            logger.error("Actual: " + verifyHash.substr(0, difficulty));
                        }
                    }
                }
                // Process ERROR command
                else if (command == "ERROR") {
                    logger.error("Server sent ERROR: " + args);
                    break;
                }
                // Process END command
                else if (command == "END") {
                    logger.success("Server sent END command: " + args);
                    logger.command(">>>", "OK", "");
                    m_connection.writeLine("OK");
                    break;
                }
                // Handle other commands by responding with authData + SHA1 checksum
                else {
                    // Generate different authData variants for testing
                    std::string checksumBase = authData + args;
                    std::string checksum = Utils::sha1(checksumBase);
                    
                    logger.info("Command: " + command + ", Args: " + args);
                    logger.info("Using authData: " + authData);
                    logger.info("Checksum base: " + checksumBase);
                    logger.info("Checksum: " + checksum);
                    
                    // Dummy response (don't actually send personal data in the testing tool)
                    std::string response = checksum + " Test Response";
                    
                    logger.command(">>>", command, response);
                    if (!m_connection.writeLine(response)) {
                        logger.error("Failed to send response to " + command);
                        return false;
                    }
                }
            }
            
            logger.info("Test completed, commands received: " + std::to_string(commandsReceived));
            return true;
        }
        
        // Test multiple connections to analyze server behavior
        bool testMultipleConnections() {
            logger.header("Testing Multiple Connections");
            
            struct ConnectionResult {
                int port;
                std::string challenge;
                int difficulty;
                std::chrono::milliseconds connectTime;
                std::chrono::milliseconds firstCommandTime;
                std::chrono::milliseconds heloToPoWTime;
                bool success;
            };
            
            std::vector<ConnectionResult> results;
            
            for (int i = 0; i < m_config.connectionCount; i++) {
                logger.info("Connection test " + std::to_string(i+1) + " of " + 
                          std::to_string(m_config.connectionCount));
                
                // Create a new connection for each test
                TLSConnection conn;
                ConnectionResult result = {0, "", 0, std::chrono::milliseconds(0), 
                                         std::chrono::milliseconds(0), std::chrono::milliseconds(0), false};
                
                // Try each port or use the specified one
                int port = m_config.port > 0 ? m_config.port : VALID_PORTS[0];
                
                auto connectStart = std::chrono::high_resolution_clock::now();
                
                if (conn.connect(m_config.hostname, port, m_certFile, m_keyFile)) {
                    auto connectEnd = std::chrono::high_resolution_clock::now();
                    result.port = port;
                    result.connectTime = std::chrono::duration_cast<std::chrono::milliseconds>(connectEnd - connectStart);
                    
                    // Wait for first command (should be HELO)
                    auto firstCommandStart = std::chrono::high_resolution_clock::now();
                    std::string line = conn.readLine(DEFAULT_TIMEOUT);
                    auto firstCommandEnd = std::chrono::high_resolution_clock::now();
                    
                    result.firstCommandTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                        firstCommandEnd - firstCommandStart);
                    
                    if (line.empty()) {
                        logger.error("No command received from server");
                        conn.disconnect();
                        results.push_back(result);
                        continue;
                    }
                    
                    auto parsed = Utils::parseCommand(line);
                    std::string command = parsed.first;
                    
                    if (command != "HELO") {
                        logger.error("Expected HELO command, got: " + command);
                        conn.disconnect();
                        results.push_back(result);
                        continue;
                    }
                    
                    // Send EHLO response
                    if (!conn.writeLine("EHLO")) {
                        logger.error("Failed to send EHLO response");
                        conn.disconnect();
                        results.push_back(result);
                        continue;
                    }
                    
                    // Wait for POW command
                    auto powStart = std::chrono::high_resolution_clock::now();
                    line = conn.readLine(DEFAULT_TIMEOUT);
                    auto powEnd = std::chrono::high_resolution_clock::now();
                    
                    result.heloToPoWTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                        powEnd - powStart);
                    
                    parsed = Utils::parseCommand(line);
                    command = parsed.first;
                    std::string args = parsed.second;
                    
                    if (command != "POW") {
                        logger.error("Expected POW command, got: " + command);
                        conn.disconnect();
                        results.push_back(result);
                        continue;
                    }
                    
                    // Parse the POW challenge and difficulty
                    std::istringstream iss(args);
                    iss >> result.challenge >> result.difficulty;
                    
                    // Don't actually solve the POW, just disconnect
                    result.success = true;
                    conn.disconnect();
                }
                
                results.push_back(result);
                
                // Wait a bit between connections
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            
            // Analyze results
            logger.header("Multiple Connection Test Results");
            
            // Calculate statistics
            int successCount = 0;
            std::map<int, int> portCounts;
            std::map<int, int> difficultyCounts;
            std::set<std::string> uniqueChallenges;
            
            std::chrono::milliseconds totalConnectTime(0);
            std::chrono::milliseconds totalFirstCommandTime(0);
            std::chrono::milliseconds totalHeloToPoWTime(0);
            
            for (const auto& result : results) {
                if (result.success) {
                    successCount++;
                    portCounts[result.port]++;
                    difficultyCounts[result.difficulty]++;
                    uniqueChallenges.insert(result.challenge);
                    
                    totalConnectTime += result.connectTime;
                    totalFirstCommandTime += result.firstCommandTime;
                    totalHeloToPoWTime += result.heloToPoWTime;
                }
            }
            
            logger.info("Successful connections: " + std::to_string(successCount) + 
                      " of " + std::to_string(results.size()));
            
            if (successCount > 0) {
                // Port distribution
                logger.info("Port distribution:");
                for (const auto& pair : portCounts) {
                    double percent = (static_cast<double>(pair.second) / successCount) * 100.0;
                    logger.info("  Port " + std::to_string(pair.first) + ": " + 
                              std::to_string(pair.second) + " (" + 
                              std::to_string(percent) + "%)");
                }
                
                // Difficulty distribution
                logger.info("Difficulty distribution:");
                for (const auto& pair : difficultyCounts) {
                    double percent = (static_cast<double>(pair.second) / successCount) * 100.0;
                    logger.info("  Difficulty " + std::to_string(pair.first) + ": " + 
                              std::to_string(pair.second) + " (" + 
                              std::to_string(percent) + "%)");
                }
                
                // Challenge uniqueness
                logger.info("Unique challenges: " + std::to_string(uniqueChallenges.size()) + 
                          " of " + std::to_string(successCount));
                
                // Average timings
                double avgConnectTime = totalConnectTime.count() / static_cast<double>(successCount);
                double avgFirstCommandTime = totalFirstCommandTime.count() / static_cast<double>(successCount);
                double avgHeloToPoWTime = totalHeloToPoWTime.count() / static_cast<double>(successCount);
                
                logger.info("Average connect time: " + std::to_string(avgConnectTime) + " ms");
                logger.info("Average time to first command: " + std::to_string(avgFirstCommandTime) + " ms");
                logger.info("Average time from HELO to POW: " + std::to_string(avgHeloToPoWTime) + " ms");
            }
            
            return successCount > 0;
        }
        
        // Test different authData variants to understand what the server expects
        bool testAuthDataVariants() {
            if (!m_connected) {
                logger.error("Not connected, cannot run test");
                return false;
            }
            
            logger.header("Testing AuthData Variants");
            
            // Initialize variables
            std::string powLine;
            std::string powCommand;
            std::string powArgs;
            std::string challenge;
            std::string difficulty;
            
            // Capture the POW command
            while (m_connected) {
                // Read a line
                logger.debug("Waiting for command...");
                std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                
                if (line.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                // Parse the command
                auto parsed = Utils::parseCommand(line);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                logger.command("<<<", command, args);
                
                if (command == "HELO") {
                    logger.command(">>>", "EHLO", "");
                    if (!m_connection.writeLine("EHLO")) {
                        logger.error("Failed to send EHLO response");
                        return false;
                    }
                }
                else if (command == "POW") {
                    // Store the POW details
                    powLine = line;
                    powCommand = command;
                    powArgs = args;
                    
                    std::istringstream iss(args);
                    iss >> challenge >> difficulty;
                    
                    // Solve the POW
                    logger.info("Solving POW challenge...");
                    int diff = std::stoi(difficulty);
                    
                    POWThreadPool powSolver(POW_THREAD_COUNT, challenge, diff);
                    auto solverResult = powSolver.waitForSolution();
                    
                    if (solverResult.solution.empty()) {
                        logger.error("Failed to find POW solution");
                        return false;
                    }
                    
                    logger.info("Found POW solution: " + solverResult.solution);
                    logger.command(">>>", solverResult.solution, "");
                    if (!m_connection.writeLine(solverResult.solution)) {
                        logger.error("Failed to send POW solution");
                        return false;
                    }
                    
                    break;
                }
                else if (command == "ERROR") {
                    logger.error("Server sent ERROR: " + args);
                    return false;
                }
            }
            
            // Now test different authData variants with the next command
            std::vector<std::pair<std::string, std::string>> variants = {
                {"full", powLine},
                {"command", powCommand},
                {"args", powArgs},
                {"challenge", challenge},
                {"challenge+difficulty", challenge + " " + difficulty},
            };
            
            // Wait for the next command to test variants
            std::string nextCommandLine = m_connection.readLine(DEFAULT_TIMEOUT);
            if (nextCommandLine.empty() && !m_connection.isConnected()) {
                logger.error("Connection closed by server");
                return false;
            }
            
            auto parsed = Utils::parseCommand(nextCommandLine);
            std::string nextCommand = parsed.first;
            std::string nextArgs = parsed.second;
            
            logger.command("<<<", nextCommand, nextArgs);
            
            // Test each variant by computing different checksums
            logger.info("Testing authData variants for command: " + nextCommand + " " + nextArgs);
            
            for (const auto& variant : variants) {
                std::string variantName = variant.first;
                std::string authData = variant.second;
                
                std::string checksumBase = authData + nextArgs;
                std::string checksum = Utils::sha1(checksumBase);
                
                logger.info("Variant: " + variantName);
                logger.info("  AuthData: " + authData);
                logger.info("  Checksum base: " + checksumBase);
                logger.info("  Checksum: " + checksum);
            }
            
            // Respond with the authData variant specified in the config
            std::string authData;
            if (m_config.authDataVariant == "full") {
                authData = powLine;
            }
            else if (m_config.authDataVariant == "command") {
                authData = powCommand;
            }
            else if (m_config.authDataVariant == "args") {
                authData = powArgs;
            }
            else if (m_config.authDataVariant == "challenge") {
                authData = challenge;
            }
            else if (m_config.authDataVariant == "challenge+difficulty") {
                authData = challenge + " " + difficulty;
            }
            else {
                // Default
                authData = challenge;
            }
            
            std::string checksum = Utils::sha1(authData + nextArgs);
            std::string response = checksum + " Test Response";
            
            logger.info("Responding with variant: " + m_config.authDataVariant);
            logger.command(">>>", nextCommand, response);
            
            if (!m_connection.writeLine(response)) {
                logger.error("Failed to send response with variant: " + m_config.authDataVariant);
                return false;
            }
            
            // Wait for server response
            std::string serverResponse = m_connection.readLine(DEFAULT_TIMEOUT);
            if (serverResponse.empty() && !m_connection.isConnected()) {
                logger.error("Connection closed by server");
                return false;
            }
            
            parsed = Utils::parseCommand(serverResponse);
            std::string responseCommand = parsed.first;
            std::string responseArgs = parsed.second;
            
            logger.command("<<<", responseCommand, responseArgs);
            
            if (responseCommand == "ERROR") {
                logger.error("Server rejected variant '" + m_config.authDataVariant + "': " + responseArgs);
                return false;
            }
            
            logger.success("Server accepted variant: " + m_config.authDataVariant);
            return true;
        }
        
        // Test solving POW with different solutions
        bool testPOWSolutions() {
            if (!m_connected) {
                logger.error("Not connected, cannot run test");
                return false;
            }
            
            logger.header("Testing POW Solutions");
            
            // Initialize variables
            std::/**
     * TLS Protocol Diagnostic Tool
     * 
     * A specialized tool for testing and analyzing the Exatest server behavior,
     * particularly focused on understanding the POW challenge mechanism.
     * 
     * Based on the Optimized TLS Protocol Client.
     * 
     * Compilation:
     * g++ -Wall -Wextra -g3 -O3 -std=c++17 tls_diagnostic_tool.cpp -o tls_diagnostic_tool.exe -lssl -lcrypto -lws2_32 -pthread
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
    
    // Logger class with thread safety
    class Logger {
    public:
        enum Level {
            DEBUG,
            INFO,
            WARNING,
            ERROR
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
    Logger logger;
    
    // Set of valid ports to try
    const std::vector<int> VALID_PORTS = {3336, 8083, 8446, 49155, 3481, 65532};
    
    // Hostname for the Exatest server
    const std::string SERVER_HOSTNAME = "18.202.148.130";
    
    // Timeout values in seconds
    const int POW_TIMEOUT = 7200;    // 2 hours
    const int DEFAULT_TIMEOUT = 6;   // 6 seconds
    
    // Thread pool size for POW calculations
    const int POW_THREAD_COUNT = std::max(1u, std::thread::hardware_concurrency());
    
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
                logger.header("Testing POW Solutions");
        
                // Initialize variables
                std::string challenge;
                int difficulty = 0;
                
                // Get to the POW challenge
                while (m_connected) {
                    std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                    
                    if (line.empty() && !m_connection.isConnected()) {
                        logger.error("Connection closed by server");
                        return false;
                    }
                    
                    auto parsed = Utils::parseCommand(line);
                    std::string command = parsed.first;
                    std::string args = parsed.second;
                    
                    logger.command("<<<", command, args);
                    
                    if (command == "HELO") {
                        logger.command(">>>", "EHLO", "");
                        if (!m_connection.writeLine("EHLO")) {
                            logger.error("Failed to send EHLO response");
                            return false;
                        }
                    }
                    else if (command == "POW") {
                        std::istringstream iss(args);
                        iss >> challenge >> difficulty;
                        
                        logger.info("Received POW challenge: " + challenge);
                        logger.info("Difficulty: " + std::to_string(difficulty));
                        break;
                    }
                    else if (command == "ERROR") {
                        logger.error("Server sent ERROR: " + args);
                        return false;
                    }
                }
                
                if (challenge.empty() || difficulty == 0) {
                    logger.error("Did not receive a valid POW challenge");
                    return false;
                }
                
                // Generate and test multiple solutions
                logger.info("Generating multiple valid solutions...");
                
                std::vector<std::string> solutions;
                std::vector<std::string> hashes;
                
                // Solve with multiple threads to find different solutions
                for (int i = 0; i < 3; i++) {
                    logger.info("Finding solution #" + std::to_string(i+1));
                    
                    POWThreadPool powSolver(POW_THREAD_COUNT, challenge, difficulty);
                    auto solverResult = powSolver.waitForSolution();
                    
                    if (solverResult.solution.empty()) {
                        logger.error("Failed to find POW solution");
                        continue;
                    }
                    
                    logger.success("Found solution #" + std::to_string(i+1) + ": " + solverResult.solution);
                    logger.info("Hash: " + solverResult.hash);
                    
                    solutions.push_back(solverResult.solution);
                    hashes.push_back(solverResult.hash);
                    
                    // If this is not the last solution, reconnect for the next test
                    if (i < 2) {
                        disconnect();
                        if (!connect()) {
                            logger.error("Failed to reconnect for next solution test");
                            return false;
                        }
                        
                        // Skip back to the POW challenge
                        bool foundPOW = false;
                        while (m_connected && !foundPOW) {
                            std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                            
                            if (line.empty() && !m_connection.isConnected()) {
                                logger.error("Connection closed by server");
                                return false;
                            }
                            
                            auto parsed = Utils::parseCommand(line);
                            std::string command = parsed.first;
                            std::string args = parsed.second;
                            
                            logger.command("<<<", command, args);
                            
                            if (command == "HELO") {
                                logger.command(">>>", "EHLO", "");
                                if (!m_connection.writeLine("EHLO")) {
                                    logger.error("Failed to send EHLO response");
                                    return false;
                                }
                            }
                            else if (command == "POW") {
                                std::string newChallenge;
                                int newDifficulty;
                                std::istringstream iss(args);
                                iss >> newChallenge >> newDifficulty;
                                
                                if (newChallenge != challenge || newDifficulty != difficulty) {
                                    logger.warning("Got different POW challenge on reconnect!");
                                    logger.warning("Old: " + challenge + " " + std::to_string(difficulty));
                                    logger.warning("New: " + newChallenge + " " + std::to_string(newDifficulty));
                                    challenge = newChallenge;
                                    difficulty = newDifficulty;
                                }
                                
                                foundPOW = true;
                            }
                            else if (command == "ERROR") {
                                logger.error("Server sent ERROR: " + args);
                                return false;
                            }
                        }
                    }
                }
                
                // Test the solutions
                logger.info("Testing solutions against server...");
                
                for (size_t i = 0; i < solutions.size(); i++) {
                    logger.info("Testing solution #" + std::to_string(i+1) + ": " + solutions[i]);
                    
                    // Send the solution
                    logger.command(">>>", solutions[i], "");
                    if (!m_connection.writeLine(solutions[i])) {
                        logger.error("Failed to send solution");
                        return false;
                    }
                    
                    // Wait for response
                    std::string response = m_connection.readLine(DEFAULT_TIMEOUT);
                    if (response.empty() && !m_connection.isConnected()) {
                        logger.error("Connection closed by server");
                        return false;
                    }
                    
                    auto parsed = Utils::parseCommand(response);
                    std::string command = parsed.first;
                    std::string args = parsed.second;
                    
                    logger.command("<<<", command, args);
                    
                    if (command == "ERROR") {
                        logger.error("Server rejected solution #" + std::to_string(i+1) + ": " + args);
                    } else {
                        logger.success("Server accepted solution #" + std::to_string(i+1));
                        // We received the next command, just disconnect and proceed
                        break;
                    }
                    
                    // If not the last solution, reconnect for the next test
                    if (i < solutions.size() - 1) {
                        disconnect();
                        if (!connect()) {
                            logger.error("Failed to reconnect for next solution test");
                            return false;
                        }
                        
                        // Skip back to the POW challenge
                        bool foundPOW = false;
                        while (m_connected && !foundPOW) {
                            std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                            
                            if (line.empty() && !m_connection.isConnected()) {
                                logger.error("Connection closed by server");
                                return false;
                            }
                            
                            auto parsed = Utils::parseCommand(line);
                            std::string command = parsed.first;
                            std::string args = parsed.second;
                            
                            logger.command("<<<", command, args);
                            
                            if (command == "HELO") {
                                logger.command(">>>", "EHLO", "");
                                if (!m_connection.writeLine("EHLO")) {
                                    logger.error("Failed to send EHLO response");
                                    return false;
                                }
                            }
                            else if (command == "POW") {
                                foundPOW = true;
                            }
                            else if (command == "ERROR") {
                                logger.error("Server sent ERROR: " + args);
                                return false;
                            }
                        }
                    }
                }
                
                logger.success("Completed POW solution testing");
                return true;
            }
            
            // Test for POW timeout behavior
            bool testPOWTimeout() {
                if (!m_connected) {
                    logger.error("Not connected, cannot run test");
                    return false;
                }
                
                logger.header("Testing POW Timeout Behavior");
                
                // Initialize variables
                std::string challenge;
                int difficulty = 0;
                
                // Get to the POW challenge
                while (m_connected) {
                    std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                    
                    if (line.empty() && !m_connection.isConnected()) {
                        logger.error("Connection closed by server");
                        return false;
                    }
                    
                    auto parsed = Utils::parseCommand(line);
                    std::string command = parsed.first;
                    std::string args = parsed.second;
                    
                    logger.command("<<<", command, args);
                    
                    if (command == "HELO") {
                        logger.command(">>>", "EHLO", "");
                        if (!m_connection.writeLine("EHLO")) {
                            logger.error("Failed to send EHLO response");
                            return false;
                        }
                    }
                    else if (command == "POW") {
                        std::istringstream iss(args);
                        iss >> challenge >> difficulty;
                        
                        logger.info("Received POW challenge: " + challenge);
                        logger.info("Difficulty: " + std::to_string(difficulty));
                        break;
                    }
                    else if (command == "ERROR") {
                        logger.error("Server sent ERROR: " + args);
                        return false;
                    }
                }
                
                if (challenge.empty() || difficulty == 0) {
                    logger.error("Did not receive a valid POW challenge");
                    return false;
                }
                
                // Wait for a timeout (but less than the full 2 hours)
                int waitTime = 60; // 1 minute for testing, adjust as needed
                logger.info("Waiting " + std::to_string(waitTime) + " seconds to test partial timeout behavior...");
                
                std::this_thread::sleep_for(std::chrono::seconds(waitTime));
                
                // Check if server is still responsive
                logger.info("Testing if server is still responsive after " + std::to_string(waitTime) + " seconds");
                
                // Send an invalid solution intentionally
                std::string invalidSolution = "INVALID_SOLUTION";
                logger.command(">>>", invalidSolution, "");
                
                if (!m_connection.writeLine(invalidSolution)) {
                    logger.error("Failed to send invalid solution");
                    return false;
                }
                
                // Wait for response
                std::string response = m_connection.readLine(DEFAULT_TIMEOUT);
                if (response.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server after " + std::to_string(waitTime) + " seconds");
                    return false;
                }
                
                auto parsed = Utils::parseCommand(response);
                std::string command = parsed.first;
                std::string args = parsed.second;
                
                logger.command("<<<", command, args);
                
                if (command == "ERROR") {
                    logger.success("Server still responsive after " + std::to_string(waitTime) + 
                                 " seconds, rejected invalid solution: " + args);
                } else {
                    logger.warning("Unexpected response from server after " + std::to_string(waitTime) + 
                                 " seconds: " + command + " " + args);
                }
                
                return true;
            }
            
            // Test response timing for various commands
            bool testResponseTiming() {
                if (!m_connected) {
                    logger.error("Not connected, cannot run test");
                    return false;
                }
                
                logger.header("Testing Server Response Timing");
                
                // Maps to store timing data
                std::map<std::string, std::vector<std::chrono::milliseconds>> commandReceiveTimes;
                std::map<std::string, std::vector<std::chrono::milliseconds>> commandRespondTimes;
                
                // Initialize variables
                std::string authData;
                bool isFirstCommand = true;
                bool powSolved = false;
                
                // Process commands and time responses
                while (m_connected) {
                    // Read a line
                    logger.debug("Waiting for next command...");
                    std::string line;
                    
                    auto receiveStart = std::chrono::high_resolution_clock::now();
                    
                    // Use the appropriate timeout
                    int timeout = powSolved ? POW_TIMEOUT : DEFAULT_TIMEOUT;
                    line = m_connection.readLine(timeout);
                    
                    auto receiveEnd = std::chrono::high_resolution_clock::now();
                    auto receiveDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        receiveEnd - receiveStart);
                    
                    if (line.empty() && !m_connection.isConnected()) {
                        logger.error("Connection closed by server");
                        break;
                    }
                    
                    // Parse the command
                    auto parsed = Utils::parseCommand(line);
                    std::string command = parsed.first;
                    std::string args = parsed.second;
                    
                    // Record receive time
                    commandReceiveTimes[command].push_back(receiveDuration);
                    
                    logger.command("<<<", command, args);
                    logger.info("Received " + command + " in " + Utils::formatDuration(receiveDuration));
                    
                    // Process the command
                    if (command == "ERROR") {
                        logger.error("Server sent ERROR: " + args);
                        break;
                    } else if (command == "END") {
                        logger.success("Server sent END: Protocol completed successfully");
                        
                        auto respondStart = std::chrono::high_resolution_clock::now();
                        
                        logger.command(">>>", "OK", "");
                        if (!m_connection.writeLine("OK")) {
                            logger.error("Failed to send OK response");
                            break;
                        }
                        
                        auto respondEnd = std::chrono::high_resolution_clock::now();
                        auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            respondEnd - respondStart);
                        
                        commandRespondTimes[command].push_back(respondDuration);
                        logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                        
                        break;
                    } else if (command == "HELO") {
                        auto respondStart = std::chrono::high_resolution_clock::now();
                        
                        logger.command(">>>", "EHLO", "");
                        if (!m_connection.writeLine("EHLO")) {
                            logger.error("Failed to send EHLO response");
                            break;
                        }
                        
                        auto respondEnd = std::chrono::high_resolution_clock::now();
                        auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            respondEnd - respondStart);
                        
                        commandRespondTimes[command].push_back(respondDuration);
                        logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                        
                        isFirstCommand = false;
                    } else if (command == "POW") {
                        std::istringstream iss(args);
                        std::string challengeStr, difficultyStr;
                        iss >> challengeStr >> difficultyStr;
                        
                        if (challengeStr.empty() || difficultyStr.empty()) {
                            logger.error("Invalid POW challenge format: " + args);
                            break;
                        }
                        
                        int difficulty = std::stoi(difficultyStr);
                        
                        // Set up authData for future commands
                        authData = challengeStr;
                        
                        // Solve the POW challenge
                        logger.info("Solving POW challenge...");
                        
                        auto respondStart = std::chrono::high_resolution_clock::now();
                        
                        // Create a dummy solution that's just the first 'difficulty' chars from the challenge
                        // Not a valid solution, but we just want to test timing
                        std::string dummySolution = challengeStr.substr(0, std::min(8, static_cast<int>(challengeStr.length())));
                        
                        logger.command(">>>", dummySolution, "");
                        if (!m_connection.writeLine(dummySolution)) {
                            logger.error("Failed to send dummy POW solution");
                            break;
                        }
                        
                        auto respondEnd = std::chrono::high_resolution_clock::now();
                        auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            respondEnd - respondStart);
                        
                        commandRespondTimes[command].push_back(respondDuration);
                        logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                        
                        powSolved = true;
                    } else {
                        // Handle other commands by responding quickly with a dummy response
                        auto respondStart = std::chrono::high_resolution_clock::now();
                        
                        // Generate a dummy response with valid checksum
                        std::string checksum = Utils::sha1(authData + args);
                        std::string response = checksum + " DummyResponse";
                        
                        logger.command(">>>", command, response);
                        if (!m_connection.writeLine(response)) {
                            logger.error("Failed to send response to " + command);
                            break;
                        }
                        
                        auto respondEnd = std::chrono::high_resolution_clock::now();
                        auto respondDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            respondEnd - respondStart);
                        
                        commandRespondTimes[command].push_back(respondDuration);
                        logger.info("Responded to " + command + " in " + Utils::formatDuration(respondDuration));
                    }
                }
                
                // Analyze timing results
                logger.header("Server Response Timing Analysis");
                
                // Calculate averages for receive times
                logger.info("Command Receive Timing (server -> client):");
                for (const auto& pair : commandReceiveTimes) {
                    double avgTime = 0.0;
                    double minTime = std::numeric_limits<double>::max();
                    double maxTime = 0.0;
                    
                    for (const auto& time : pair.second) {
                        double ms = time.count();
                        avgTime += ms;
                        minTime = std::min(minTime, ms);
                        maxTime = std::max(maxTime, ms);
                    }
                    
                    avgTime /= pair.second.size();
                    
                    logger.info("  " + pair.first + ": " + 
                              "Avg: " + std::to_string(avgTime) + " ms, " +
                              "Min: " + std::to_string(minTime) + " ms, " +
                              "Max: " + std::to_string(maxTime) + " ms, " +
                              "Count: " + std::to_string(pair.second.size()));
                }
                
                // Calculate averages for respond times
                logger.info("Response Processing Timing (client -> server):");
                for (const auto& pair : commandRespondTimes) {
                    double avgTime = 0.0;
                    double minTime = std::numeric_limits<double>::max();
                    double maxTime = 0.0;
                    
                    for (const auto& time : pair.second) {
                        double ms = time.count();
                        avgTime += ms;
                        minTime = std::min(minTime, ms);
                        maxTime = std::max(maxTime, ms);
                    }
                    
                    avgTime /= pair.second.size();
                    
                    logger.info("  " + pair.first + ": " + 
                              "Avg: " + std::to_string(avgTime) + " ms, " +
                              "Min: " + std::to_string(minTime) + " ms, " +
                              "Max: " + std::to_string(maxTime) + " ms, " +
                              "Count: " + std::to_string(pair.second.size()));
                }
                
                return true;
            }
            
            bool isConnected() const {
                return m_connected && m_connection.isConnected();
            }
            
            int getPort() const {
                return m_port;
            }
        
        private:
            TestConfig m_config;
            std::string m_certFile;
            std::string m_keyFile;
            TLSConnection m_connection;
            bool m_connected;
            int m_port;
        };
        
        int main(int argc, char* argv[]) {
            // Initialize Winsock
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                std::cerr << "Failed to initialize Winsock" << std::endl;
                return 1;
            }
            
            // Process command-line arguments
            DiagnosticClient::TestConfig config;
            config.hostname = SERVER_HOSTNAME;
            config.testMode = 0; // Default test mode (POW behavior)
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
                } else if (arg == "--mode" && i + 1 < argc) {
                    config.testMode = std::stoi(argv[++i]);
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
                } else if (arg == "--help") {
                    std::cout << "TLS Protocol Diagnostic Tool" << std::endl;
                    std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
                    std::cout << "Options:" << std::endl;
                    std::cout << "  --host HOSTNAME     Target hostname (default: " << SERVER_HOSTNAME << ")" << std::endl;
                    std::cout << "  --mode MODE         Test mode (default: 0)" << std::endl;
                    std::cout << "                        0: Test POW behavior" << std::endl;
                    std::cout << "                        1: Test multiple connections" << std::endl;
                    std::cout << "                        2: Test authData variants" << std::endl;
                    std::cout << "                        3: Test POW solutions" << std::endl;
                    std::cout << "                        4: Test POW timeout" << std::endl;
                    std::cout << "                        5: Test response timing" << std::endl;
                    std::cout << "  --port PORT         Use specific port (default: try all)" << std::endl;
                    std::cout << "  --auth-variant VAR  AuthData variant to use (default: challenge)" << std::endl;
                    std::cout << "                        challenge: Use challenge string" << std::endl;
                    std::cout << "                        args: Use full POW args" << std::endl;
                    std::cout << "                        full: Use full POW line" << std::endl;
                    std::cout << "  --delay-after-pow   Delay after solving POW before sending solution" << std::endl;
                    std::cout << "  --delay-seconds N   Seconds to delay (default: 10)" << std::endl;
                    std::cout << "  --max-commands N    Maximum commands to process (default: no limit)" << std::endl;
                    std::cout << "  --no-verify         Disable solution verification" << std::endl;
                    std::cout << "  --multi-conn        Test multiple connections" << std::endl;
                    std::cout << "  --conn-count N      Number of connections to test (default: 5)" << std::endl;
                    std::cout << "  --debug             Enable debug logging" << std::endl;
                    std::cout << "  --help              Display this help message" << std::endl;
                    WSACleanup(); // Clean up Winsock
                    return 0;
                }
            }
            
            // Load certificate and key from embedded strings
            config.cert = 
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
            
            config.key = 
                "-----BEGIN EC PRIVATE KEY-----\n"
                "MHcCAQEEIO1eB3IU8m/qEpWdMShCR++gZGHTjmz7MWfnEgyrvessoAoGCCqGSM49\n"
                "AwEHoUQDQgAE0WNjxYaOBrXjoBS4yulCFkjI8093T9vRq1ve5tzuYqAcqsO1qSbL\n"
                "Q3TXlSFGUDmT91WTdFt6RZk50IxRqM5YhA==\n"
                "-----END EC PRIVATE KEY-----\n";
            
            std::cout << Color::BOLD << Color::CYAN << "\n";
            std::cout << "╔════════════════════════════════════════════════════════════╗\n";
            std::cout << "║                TLS Protocol Diagnostic Tool                ║\n";
            std::cout << "╚════════════════════════════════════════════════════════════╝\n";
            std::cout << Color::RESET << std::endl;
            
            std::cout << "Target host: " << Color::BOLD << config.hostname << Color::RESET << std::endl;
            std::cout << "Test mode: " << Color::BOLD << config.testMode << Color::RESET << std::endl;
            if (config.port > 0) {
                std::cout << "Port: " << Color::BOLD << config.port << Color::RESET << std::endl;
            } else {
                std::cout << "Ports: " << Color::BOLD << "Auto (try all)" << Color::RESET << std::endl;
            }
            std::cout << "AuthData variant: " << Color::BOLD << config.authDataVariant << Color::RESET << std::endl;
            std::cout << "POW threads: " << Color::BOLD << POW_THREAD_COUNT << Color::RESET << std::endl;
            std::cout << std::endl;
            
            try {
                DiagnosticClient client(config);
                
                bool result = false;
                
                // For modes that don't need a connection first, handle them separately
                if (config.testMode == 1 && config.testMultipleConnections) {
                    logger.header("Testing Multiple Connections");
                    result = client.testMultipleConnections();
                } else {
                    // For all other modes, connect first
                    logger.header("Connecting to " + config.hostname);
                    
                    if (!client.connect()) {
                        logger.error("Failed to establish connection to " + config.hostname);
                        WSACleanup(); // Clean up Winsock
                        return 1;
                    }
                    
                    // Run the appropriate test based on mode
                    switch (config.testMode) {
                        case 0:
                            // Test POW behavior
                            result = client.testPOWBehavior();
                            break;
                        case 2:
                            // Test authData variants
                            result = client.testAuthDataVariants();
                            break;
                        case 3:
                            // Test POW solutions
                            result = client.testPOWSolutions();
                            break;
                        case 4:
                            // Test POW timeout
                            result = client.testPOWTimeout();
                            break;
                        case 5:
                            // Test response timing
                            result = client.testResponseTiming();
                            break;
                        default:
                            logger.error("Unknown test mode: " + std::to_string(config.testMode));
                            result = false;
                            break;
                    }
                    
                    client.disconnect();
                }
                
                if (        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
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
        
        // Diagnostic client for protocol testing
        class DiagnosticClient {
        public:
            struct TestConfig {
                std::string hostname;
                std::string cert;
                std::string key;
                int testMode;
                int port;
                std::string authDataVariant;
                bool delayAfterPOW;
                int delaySeconds;
                int maxCommands;
                bool verifySolutions;
                bool testMultipleConnections;
                int connectionCount;
            };
            
            DiagnosticClient(const TestConfig& config) 
                : m_config(config), 
                  m_connected(false), 
                  m_port(config.port > 0 ? config.port : VALID_PORTS[0]) {
                
                // Save certificate and key to temporary files
                try {
                    auto files = Utils::saveCertAndKey(m_config.cert, m_config.key);
                    m_certFile = files.first;
                    m_keyFile = files.second;
                    logger.debug("Saved certificate and key to temporary files");
                } catch (const std::exception& e) {
                    logger.error("Failed to save certificate and key: " + std::string(e.what()));
                }
            }
            
            ~DiagnosticClient() {
                disconnect();
                
                // Clean up temporary files if they exist
                if (!m_certFile.empty() && !m_keyFile.empty()) {
                    Utils::cleanupTempFiles(m_certFile, m_keyFile);
                }
            }
            
            // Method to connect to the server
            bool connect() {
                if (m_config.port <= 0) {
                    // Try all ports in sequence
                    for (const auto& port : VALID_PORTS) {
                        logger.header("Attempting connection on port " + std::to_string(port));
                        
                        if (m_connection.connect(m_config.hostname, port, m_certFile, m_keyFile)) {
                            m_port = port;
                            m_connected = true;
                            logger.success("Connected to " + m_config.hostname + " on port " + std::to_string(port));
                            return true;
                        }
                        
                        logger.warning("Failed to connect on port " + std::to_string(port));
                    }
                    
                    logger.error("Failed to connect to " + m_config.hostname + " on any available port");
                    return false;
                } else {
                    // Connect to the specified port
                    logger.header("Connecting to port " + std::to_string(m_config.port));
                    
                    if (m_connection.connect(m_config.hostname, m_config.port, m_certFile, m_keyFile)) {
                        m_port = m_config.port;
                        m_connected = true;
                        logger.success("Connected to " + m_config.hostname + " on port " + std::to_string(m_port));
                        return true;
                    }
                    
                    logger.error("Failed to connect to " + m_config.hostname + " on port " + std::to_string(m_config.port));
                    return false;
                }
            }
            
            void disconnect() {
                if (m_connected) {
                    m_connection.disconnect();
                    m_connected = false;
                }
            }
            
            // Test POW command behavior
            bool testPOWBehavior() {
                if (!m_connected) {
                    logger.error("Not connected, cannot run test");
                    return false;
                }
                
                logger.header("Testing POW Behavior");
                
                // Initialize authData and other variables
                std::string authData;
                int commandsReceived = 0;
                
                // Start the protocol sequence
                while (m_connected && (m_config.maxCommands <= 0 || commandsReceived < m_config.maxCommands)) {
                    // Read a line
                    logger.debug("Waiting for next command...");
                    std::string line;
                    
                    // Use the appropriate timeout
                    int timeout = DEFAULT_TIMEOUT;
                    if (!authData.empty()) {
                        // If we're in POW mode, use the longer timeout
                        timeout = POW_TIMEOUT;
                    }
                    
                    line = m_connection.readLine(timeout);
                    commandsReceived++;
                    
                    if (line.empty() && !m_connection.isConnected()) {
                        logger.error("Connection closed by server");
                        return false;
                    }
                    
                    // Parse the command
                    auto parsed = Utils::parseCommand(line);
                    std::string command = parsed.first;
                    std::string args = parsed.second;
                    
                    logger.command("<<<", command, args);
                    
                    // Process HELO command
                    if (command == "HELO") {
                        logger.info("Received HELO command");
                        logger.command(">>>", "EHLO", "");
                        
                        auto startTime = std::chrono::high_resolution_clock::now();
                        
                        if (!m_connection.writeLine("EHLO")) {
                            logger.error("Failed to send EHLO response");
                            return false;
                        }
                        
                        auto endTime = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                        
                        logger.info("EHLO response sent in " + Utils::formatDuration(duration));
                    }
                    // Process POW command
                    else if (command == "POW") {
                        logger.info("Received POW command");
                        
                        // Parse POW parameters
                        std::istringstream iss(args);
                        std::string challengeStr, difficultyStr;
                        iss >> challengeStr >> difficultyStr;
                        
                        if (challengeStr.empty() || difficultyStr.empty()) {
                            logger.error("Invalid POW challenge format: " + args);
                            return false;
                        }
                        
                        int difficulty = std::stoi(difficultyStr);
                        
                        // Store the full POW line and arguments
                        std::string fullPOWLine = line;
                        std::string fullPOWArgs = args;
                        
                        // Set authData based on config
                        if (m_config.authDataVariant == "full") {
                            authData = fullPOWLine;
                            logger.info("Using full POW line as authData: " + authData);
                        }
                        else if (m_config.authDataVariant == "args") {
                            authData = fullPOWArgs;
                            logger.info("Using POW args as authData: " + authData);
                        }
                        else if (m_config.authDataVariant == "challenge") {
                            authData = challengeStr;
                            logger.info("Using challenge string as authData: " + authData);
                        }
                        else {
                            // Default behavior
                            authData = challengeStr;
                            logger.info("Using challenge string as authData (default): " + authData);
                        }
                        
                        // Log the challenge characteristics
                        logger.info("Challenge length: " + std::to_string(challengeStr.length()) + " characters");
                        logger.info("Difficulty: " + difficultyStr);
                        
                        // Analyze challenge string
                        std::map<char, int> charCounts;
                        for (char c : challengeStr) {
                            charCounts[c]++;
                        }
                        
                        logger.info("Challenge character distribution:");
                        for (const auto& pair : charCounts) {
                            logger.debug("'" + std::string(1, pair.first) + "': " + std::to_string(pair.second));
                        }
                        
                        // Solve the POW challenge
                        logger.info("Starting POW solver with " + std::to_string(POW_THREAD_COUNT) + " threads");
                        
                        auto startTime = std::chrono::high_resolution_clock::now();
                        
                        POWThreadPool powSolver(POW_THREAD_COUNT, challengeStr, difficulty);
                        auto solverResult = powSolver.waitForSolution();
                        
                        auto endTime = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                        
                        if (solverResult.solution.empty()) {
                            logger.error("Failed to find POW solution");
                            return false;
                        }
                        
                        logger.success("Found POW solution in " + Utils::formatDuration(solverResult.duration));
                        logger.info("Solution: " + solverResult.solution);
                        logger.info("Hash: " + solverResult.hash);
                        logger.info("Thread ID: " + std::to_string(solverResult.threadId));
                        logger.info("Attempts: " + std::to_string(solverResult.attempts));
                        
                        double hashRate = static_cast<double>(solverResult.attempts) / (solverResult.duration.count() / 1000.0);
                        logger.info("Hash rate: " + std::to_string(static_cast<uint64_t>(hashRate)) + " hashes/sec");
                        
                        // Optional delay after POW to see if server behavior changes
                        if (m_config.delayAfterPOW) {
                            logger.info("Delaying response for " + std::to_string(m_config.delaySeconds) + " seconds");
                            std::this_thread::sleep_for(std::chrono::seconds(m_config.delaySeconds));
                        }
                        
                        // Send the solution
                        logger.command(">>>", solverResult.solution, "");
                        if (!m_connection.writeLine(solverResult.solution)) {
                            logger.error("Failed to send POW solution");
                            return false;
                        }
                        
                        // If verifying solutions, check the solution is valid
                        if (m_config.verifySolutions) {
                            std::string verifyHash = Utils::sha1(challengeStr + solverResult.solution);
                            std::string reqPrefix(difficulty, '0');
                            bool valid = verifyHash.substr(0, difficulty) == reqPrefix;
                            
                            logger.info("Solution verification: " + std::string(valid ? "VALID" : "INVALID"));
                            if (!valid) {
                                logger.error("Solution hash doesn't match required prefix!");
                                logger.error("Required: " + reqPrefix);
                                logger.error("Actual: " + verifyHash.substr(0, difficulty));
                            }
                        }
                    }
                    // Process ERROR command
                    else if (command == "ERROR") {
                        logger.error("Server sent ERROR: " + args);
                        break;
                    }
                    // Process END command
                    else if (command == "END") {
                        logger.success("Server sent END command: " + args);
                        logger.command(">>>", "OK", "");
                        m_connection.writeLine("OK");
                        break;
                    }
                    // Handle other commands by responding with authData + SHA1 checksum
                    else {
                        // Generate different authData variants for testing
                        std::string checksumBase = authData + args;
                        std::string checksum = Utils::sha1(checksumBase);
                        
                        logger.info("Command: " + command + ", Args: " + args);
                        logger.info("Using authData: " + authData);
                        logger.info("Checksum base: " + checksumBase);
                        logger.info("Checksum: " + checksum);
                        
                        // Dummy response (don't actually send personal data in the testing tool)
                        std::string response = checksum + " Test Response";
                        
                        logger.command(">>>", command, response);
                        if (!m_connection.writeLine(response)) {
                            logger.error("Failed to send response to " + command);
                            return false;
                        }
                    }
                }
                
                logger.info("Test completed, commands received: " + std::to_string(commandsReceived));
                return true;
            }
            
            // Test multiple connections to analyze server behavior
            bool testMultipleConnections() {
                logger.header("Testing Multiple Connections");
                
                struct ConnectionResult {
                    int port;
                    std::string challenge;
                    int difficulty;
                    std::chrono::milliseconds connectTime;
                    std::chrono::milliseconds firstCommandTime;
                    std::chrono::milliseconds heloToPoWTime;
                    bool success;
                };
                
                std::vector<ConnectionResult> results;
                
                for (int i = 0; i < m_config.connectionCount; i++) {
                    logger.info("Connection test " + std::to_string(i+1) + " of " + 
                              std::to_string(m_config.connectionCount));
                    
                    // Create a new connection for each test
                    TLSConnection conn;
                    ConnectionResult result = {0, "", 0, std::chrono::milliseconds(0), 
                                             std::chrono::milliseconds(0), std::chrono::milliseconds(0), false};
                    
                    // Try each port or use the specified one
                    int port = m_config.port > 0 ? m_config.port : VALID_PORTS[0];
                    
                    auto connectStart = std::chrono::high_resolution_clock::now();
                    
                    if (conn.connect(m_config.hostname, port, m_certFile, m_keyFile)) {
                        auto connectEnd = std::chrono::high_resolution_clock::now();
                        result.port = port;
                        result.connectTime = std::chrono::duration_cast<std::chrono::milliseconds>(connectEnd - connectStart);
                        
                        // Wait for first command (should be HELO)
                        auto firstCommandStart = std::chrono::high_resolution_clock::now();
                        std::string line = conn.readLine(DEFAULT_TIMEOUT);
                        auto firstCommandEnd = std::chrono::high_resolution_clock::now();
                        
                        result.firstCommandTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                            firstCommandEnd - firstCommandStart);
                        
                        if (line.empty()) {
                            logger.error("No command received from server");
                            conn.disconnect();
                            results.push_back(result);
                            continue;
                        }
                        
                        auto parsed = Utils::parseCommand(line);
                        std::string command = parsed.first;
                        
                        if (command != "HELO") {
                            logger.error("Expected HELO command, got: " + command);
                            conn.disconnect();
                            results.push_back(result);
                            continue;
                        }
                        
                        // Send EHLO response
                        if (!conn.writeLine("EHLO")) {
                            logger.error("Failed to send EHLO response");
                            conn.disconnect();
                            results.push_back(result);
                            continue;
                        }
                        
                        // Wait for POW command
                        auto powStart = std::chrono::high_resolution_clock::now();
                        line = conn.readLine(DEFAULT_TIMEOUT);
                        auto powEnd = std::chrono::high_resolution_clock::now();
                        
                        result.heloToPoWTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                            powEnd - powStart);
                        
                        parsed = Utils::parseCommand(line);
                        command = parsed.first;
                        std::string args = parsed.second;
                        
                        if (command != "POW") {
                            logger.error("Expected POW command, got: " + command);
                            conn.disconnect();
                            results.push_back(result);
                            continue;
                        }
                        
                        // Parse the POW challenge and difficulty
                        std::istringstream iss(args);
                        iss >> result.challenge >> result.difficulty;
                        
                        // Don't actually solve the POW, just disconnect
                        result.success = true;
                        conn.disconnect();
                    }
                    
                    results.push_back(result);
                    
                    // Wait a bit between connections
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                
                // Analyze results
                logger.header("Multiple Connection Test Results");
                
                // Calculate statistics
                int successCount = 0;
                std::map<int, int> portCounts;
                std::map<int, int> difficultyCounts;
                std::set<std::string> uniqueChallenges;
                
                std::chrono::milliseconds totalConnectTime(0);
                std::chrono::milliseconds totalFirstCommandTime(0);
                std::chrono::milliseconds totalHeloToPoWTime(0);
                
                for (const auto& result : results) {
                    if (result.success) {
                        successCount++;
                        portCounts[result.port]++;
                        difficultyCounts[result.difficulty]++;
                        uniqueChallenges.insert(result.challenge);
                        
                        totalConnectTime += result.connectTime;
                        totalFirstCommandTime += result.firstCommandTime;
                        totalHeloToPoWTime += result.heloToPoWTime;
                    }
                }
                
                logger.info("Successful connections: " + std::to_string(successCount) + 
                          " of " + std::to_string(results.size()));
                
                if (successCount > 0) {
                    // Port distribution
                    logger.info("Port distribution:");
                    for (const auto& pair : portCounts) {
                        double percent = (static_cast<double>(pair.second) / successCount) * 100.0;
                        logger.info("  Port " + std::to_string(pair.first) + ": " + 
                                  std::to_string(pair.second) + " (" + 
                                  std::to_string(percent) + "%)");
                    }
                    
                    // Difficulty distribution
                    logger.info("Difficulty distribution:");
                    for (const auto& pair : difficultyCounts) {
                        double percent = (static_cast<double>(pair.second) / successCount) * 100.0;
                        logger.info("  Difficulty " + std::to_string(pair.first) + ": " + 
                                  std::to_string(pair.second) + " (" + 
                                  std::to_string(percent) + "%)");
                    }
                    
                    // Challenge uniqueness
                    logger.info("Unique challenges: " + std::to_string(uniqueChallenges.size()) + 
                              " of " + std::to_string(successCount));
                    
                    // Average timings
                    double avgConnectTime = totalConnectTime.count() / static_cast<double>(successCount);
                    double avgFirstCommandTime = totalFirstCommandTime.count() / static_cast<double>(successCount);
                    double avgHeloToPoWTime = totalHeloToPoWTime.count() / static_cast<double>(successCount);
                    
                    logger.info("Average connect time: " + std::to_string(avgConnectTime) + " ms");
                    logger.info("Average time to first command: " + std::to_string(avgFirstCommandTime) + " ms");
                    logger.info("Average time from HELO to POW: " + std::to_string(avgHeloToPoWTime) + " ms");
                }
                
                return successCount > 0;
            }
            
            // Test different authData variants to understand what the server expects
            bool testAuthDataVariants() {
                if (!m_connected) {
                    logger.error("Not connected, cannot run test");
                    return false;
                }
                
                logger.header("Testing AuthData Variants");
                
                // Initialize variables
                std::string powLine;
                std::string powCommand;
                std::string powArgs;
                std::string challenge;
                std::string difficulty;
                
                // Capture the POW command
                while (m_connected) {
                    // Read a line
                    logger.debug("Waiting for command...");
                    std::string line = m_connection.readLine(DEFAULT_TIMEOUT);
                    
                    if (line.empty() && !m_connection.isConnected()) {
                        logger.error("Connection closed by server");
                        return false;
                    }
                    
                    // Parse the command
                    auto parsed = Utils::parseCommand(line);
                    std::string command = parsed.first;
                    std::string args = parsed.second;
                    
                    logger.command("<<<", command, args);
                    
                    if (command == "HELO") {
                        logger.command(">>>", "EHLO", "");
                        if (!m_connection.writeLine("EHLO")) {
                            logger.error("Failed to send EHLO response");
                            return false;
                        }
                    }
                    else if (command == "POW") {
                        // Store the POW details
                        powLine = line;
                        powCommand = command;
                        powArgs = args;
                        
                        std::istringstream iss(args);
                        iss >> challenge >> difficulty;
                        
                        // Solve the POW
                        logger.info("Solving POW challenge...");
                        int diff = std::stoi(difficulty);
                        
                        POWThreadPool powSolver(POW_THREAD_COUNT, challenge, diff);
                        auto solverResult = powSolver.waitForSolution();
                        
                        if (solverResult.solution.empty()) {
                            logger.error("Failed to find POW solution");
                            return false;
                        }
                        
                        logger.info("Found POW solution: " + solverResult.solution);
                        logger.command(">>>", solverResult.solution, "");
                        if (!m_connection.writeLine(solverResult.solution)) {
                            logger.error("Failed to send POW solution");
                            return false;
                        }
                        
                        break;
                    }
                    else if (command == "ERROR") {
                        logger.error("Server sent ERROR: " + args);
                        return false;
                    }
                }
                
                // Now test different authData variants with the next command
                std::vector<std::pair<std::string, std::string>> variants = {
                    {"full", powLine},
                    {"command", powCommand},
                    {"args", powArgs},
                    {"challenge", challenge},
                    {"challenge+difficulty", challenge + " " + difficulty},
                };
                
                // Wait for the next command to test variants
                std::string nextCommandLine = m_connection.readLine(DEFAULT_TIMEOUT);
                if (nextCommandLine.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                auto parsed = Utils::parseCommand(nextCommandLine);
                std::string nextCommand = parsed.first;
                std::string nextArgs = parsed.second;
                
                logger.command("<<<", nextCommand, nextArgs);
                
                // Test each variant by computing different checksums
                logger.info("Testing authData variants for command: " + nextCommand + " " + nextArgs);
                
                for (const auto& variant : variants) {
                    std::string variantName = variant.first;
                    std::string authData = variant.second;
                    
                    std::string checksumBase = authData + nextArgs;
                    std::string checksum = Utils::sha1(checksumBase);
                    
                    logger.info("Variant: " + variantName);
                    logger.info("  AuthData: " + authData);
                    logger.info("  Checksum base: " + checksumBase);
                    logger.info("  Checksum: " + checksum);
                }
                
                // Respond with the authData variant specified in the config
                std::string authData;
                if (m_config.authDataVariant == "full") {
                    authData = powLine;
                }
                else if (m_config.authDataVariant == "command") {
                    authData = powCommand;
                }
                else if (m_config.authDataVariant == "args") {
                    authData = powArgs;
                }
                else if (m_config.authDataVariant == "challenge") {
                    authData = challenge;
                }
                else if (m_config.authDataVariant == "challenge+difficulty") {
                    authData = challenge + " " + difficulty;
                }
                else {
                    // Default
                    authData = challenge;
                }
                
                std::string checksum = Utils::sha1(authData + nextArgs);
                std::string response = checksum + " Test Response";
                
                logger.info("Responding with variant: " + m_config.authDataVariant);
                logger.command(">>>", nextCommand, response);
                
                if (!m_connection.writeLine(response)) {
                    logger.error("Failed to send response with variant: " + m_config.authDataVariant);
                    return false;
                }
                
                // Wait for server response
                std::string serverResponse = m_connection.readLine(DEFAULT_TIMEOUT);
                if (serverResponse.empty() && !m_connection.isConnected()) {
                    logger.error("Connection closed by server");
                    return false;
                }
                
                parsed = Utils::parseCommand(serverResponse);
                std::string responseCommand = parsed.first;
                std::string responseArgs = parsed.second;
                
                logger.command("<<<", responseCommand, responseArgs);
                
                if (responseCommand == "ERROR") {
                    logger.error("Server rejected variant '" + m_config.authDataVariant + "': " + responseArgs);
                    return false;
                }
                
                logger.success("Server accepted variant: " + m_config.authDataVariant);
                return true;
            }
            
            // Test solving POW with different solutions
            bool testPOWSolutions() {
                if (!m_connected) {
                    logger.error("Not connected, cannot run test");
                    return false;
                }
                
                logger.header("Testing POW Solutions");
                
                // Initialize variables
                std::/**
         * TLS Protocol Diagnostic Tool
         * 
         * A specialized tool for testing and analyzing the Exatest server behavior,
         * particularly focused on understanding the POW challenge mechanism.
         * 
         * Based on the Optimized TLS Protocol Client.
         * 
         * Compilation:
         * g++ -Wall -Wextra -g3 -O3 -std=c++17 tls_diagnostic_tool.cpp -o tls_diagnostic_tool.exe -lssl -lcrypto -lws2_32 -pthread
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
        
        // Logger class with thread safety
        class Logger {
        public:
            enum Level {
                DEBUG,
                INFO,
                WARNING,
                ERROR
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
        Logger logger;
        
        // Set of valid ports to try
        const std::vector<int> VALID_PORTS = {3336, 8083, 8446, 49155, 3481, 65532};
        
        // Hostname for the Exatest server
        const std::string SERVER_HOSTNAME = "18.202.148.130";
        
        // Timeout values in seconds
        const int POW_TIMEOUT = 7200;    // 2 hours
        const int DEFAULT_TIMEOUT = 6;   // 6 seconds
        
        // Thread pool size for POW calculations
        const int POW_THREAD_COUNT = std::max(1u, std::thread::hardware_concurrency());
        
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