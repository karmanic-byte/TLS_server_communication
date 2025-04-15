/**
 * Optimized TLS Protocol Client
 * 
 * A highly optimized client for communicating with the Exatest server:
 * - Multi-threaded POW solver for maximum performance
 * - Proper TLS certificate handling
 * - Robust timeout management (POW: 2 hours, others: 6 seconds)
 * - Automatic port selection from available options
 * - UTF-8 validation and handling
 * - Line-oriented protocol implementation
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
 const std::vector<int> VALID_PORTS = { 8083, 8446, 49155, 3481,3336, 65532};
 
 // Hostname for the Exatest server
 const std::string SERVER_HOSTNAME = "18.202.148.130";
 
 // Timeout values in seconds
 const int POW_TIMEOUT = 7200;    // 2 hours
 const int DEFAULT_TIMEOUT = 6;   // 6 seconds
 
 // Thread pool size for POW calculations
 const int POW_THREAD_COUNT = std::max(1u, std::thread::hardware_concurrency());
 
 // The maximum number of random candidates to test per batch in POW
 const int POW_BATCH_SIZE = 100000;
 
 // List of valid country names
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
 
 // Thread pool for parallel POW computation
 class POWThreadPool {
 public:
     POWThreadPool(int numThreads, const std::string& challenge, int difficulty) 
         : m_challenge(challenge), m_difficulty(difficulty), m_targetPrefix(difficulty, '0'),
           m_running(true), m_found(false) {
         
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
     std::string waitForSolution() {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_condition.wait(lock, [this] { return m_found || !m_running; });
         
         if (m_found) {
             return m_solution;
         }
         
         return "";
     }
 
 private:
     void workerThread(int id) {
         logger.debug("POW Worker thread " + std::to_string(id) + " started");
         
         std::random_device rd;
         std::mt19937 gen(rd() + id); // Add thread ID to seed for better distribution
         
         // Smaller suffix for faster computation and transmission
         const int suffixLength = 8; 
         
         while (true) {
             // Check if we should stop
             {
                 std::lock_guard<std::mutex> lock(m_mutex);
                 if (!m_running || m_found) {
                     break;
                 }
             }
             
             // Process a batch of random strings
             for (int i = 0; i < POW_BATCH_SIZE; ++i) {
                 // Generate random suffix
                 std::string suffix = Utils::randomPowString(suffixLength);
                 
                 // Compute SHA-1 hash
                 std::string hash = Utils::sha1(m_challenge + suffix);
                 
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
                     return;
                 }
             }
             
             // Periodically check if another thread found a solution
             {
                 std::lock_guard<std::mutex> lock(m_mutex);
                 if (m_found || !m_running) {
                     break;
                 }
             }
         }
         
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
         
         logger.debug("TCP connection established");
         
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
         
         int result;
         bool handshakeComplete = false;
         time_t startTime = time(NULL);
         const int handshakeTimeout = 10;  // 10 second handshake timeout
         
         while (!handshakeComplete && (time(NULL) - startTime) < handshakeTimeout) {
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
         
         if (!handshakeComplete) {
             logger.error("TLS handshake timed out after " + std::to_string(handshakeTimeout) + " seconds");
             SSL_free(m_ssl);
             m_ssl = nullptr;
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         logger.success("TLS handshake completed successfully");
         logger.info("Using " + std::string(SSL_get_version(m_ssl)) + " with cipher " + 
                    std::string(SSL_get_cipher(m_ssl)));
         
         // Set socket back to blocking mode for normal operations
         int sock = SSL_get_fd(m_ssl);
         u_long iMode = 0; // 0 = blocking, 1 = non-blocking
         ioctlsocket(sock, FIONBIO, &iMode);
         
         m_connected = true;
         return true;
     }
     
     void disconnect() {
         if (m_ssl) {
             SSL_shutdown(m_ssl);
             SSL_free(m_ssl);
             m_ssl = nullptr;
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
         
         // Ensure valid UTF-8
         std::string utf8_line = Utils::ensureUTF8(line);
         
         // If the line changed, it wasn't valid UTF-8
         if (utf8_line != line) {
             logger.warning("Received non-UTF-8 data, converted to valid UTF-8");
         }
         
         return utf8_line;
     }
     
     bool writeLine(const std::string& line) {
         if (!m_ssl || !m_connected) {
             logger.error("Cannot write to closed connection");
             return false;
         }
         
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
 
 // Client class for the Exatest protocol
 class ExatestClient {
 public:
     struct UserInfo {
         std::string name;
         std::vector<std::string> emails;
         std::string skype;
         std::string birthdate;
         std::string country;
         std::vector<std::string> addressLines;
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
           m_port(0) {}
     
     ~ExatestClient() {
         disconnect();
         
         // Clean up temporary files if they exist
         if (!m_certFile.empty() && !m_keyFile.empty()) {
             Utils::cleanupTempFiles(m_certFile, m_keyFile);
         }
     }
     
     bool connect() {
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
         
         // Try each port until one works
         for (const auto& port : VALID_PORTS) {
             logger.header("Attempting connection on port " + std::to_string(port));
             
             if (m_connection.connect(m_hostname, port, m_certFile, m_keyFile)) {
                 m_port = port;
                 m_connected = true;
                 logger.success("Connected to " + m_hostname + " on port " + std::to_string(port));
                 return true;
             }
             
             logger.warning("Failed to connect on port " + std::to_string(port));
         }
         
         logger.error("Failed to connect to " + m_hostname + " on any available port");
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
         
         // Process commands until END or ERROR
         while (m_connected && !end_received) {
             // Read a line
             logger.debug("Waiting for next command...");
             std::string line;
             
             // Default timeout unless we're in POW
             int timeout = DEFAULT_TIMEOUT;
             if (!authdata.empty()) {
                 // If we've received authdata but no response yet, we're probably calculating POW
                 // Use the extended timeout
                 timeout = POW_TIMEOUT;
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
                 
                 // Solve the PoW challenge using the thread pool
                 logger.info("Starting parallel POW solver with " + std::to_string(POW_THREAD_COUNT) + " threads");
                 auto startTime = std::chrono::high_resolution_clock::now();
                 
                 POWThreadPool powSolver(POW_THREAD_COUNT, challengeStr, difficulty);
                 std::string solution = powSolver.waitForSolution();
                 
                 auto endTime = std::chrono::high_resolution_clock::now();
                 auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
                 
                 if (solution.empty()) {
                     logger.error("Failed to find POW solution");
                     return false;
                 }
                 
                 logger.success("Found POW solution in " + std::to_string(duration.count()) + " seconds");
                 
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
         }
         
         // Check if protocol was completed successfully
         if (!end_received) {
             logger.error("Protocol sequence incomplete - did not receive END command");
             return false;
         }
         
         logger.success("Protocol completed successfully");
         return true;
     }
     
     bool isConnected() const {
         return m_connected && m_connection.isConnected();
     }
     
     int getPort() const {
         return m_port;
     }
 
 private:
     std::string m_hostname;
     std::string m_cert;
     std::string m_key;
     std::string m_certFile;
     std::string m_keyFile;
     UserInfo m_userInfo;
     TLSConnection m_connection;
     bool m_connected;
     int m_port;
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
     bool debug_mode = false;
     
     for (int i = 1; i < argc; ++i) {
         std::string arg = argv[i];
         if (arg == "--debug") {
             debug_mode = true;
             logger.setLevel(Logger::DEBUG);
         } else if (arg == "--help") {
             std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
             std::cout << "Options:" << std::endl;
             std::cout << "  --debug             Enable debug logging" << std::endl;
             std::cout << "  --help              Display this help message" << std::endl;
             WSACleanup(); // Clean up Winsock
             return 0;
         }
     }
     
     std::cout << Color::BOLD << Color::CYAN << "\n";
     std::cout << "╔════════════════════════════════════════════════════════════╗\n";
     std::cout << "║                   Exatest Protocol Client                  ║\n";
     std::cout << "╚════════════════════════════════════════════════════════════╝\n";
     std::cout << Color::RESET << std::endl;
     
     std::cout << "Target host: " << Color::BOLD << SERVER_HOSTNAME << Color::RESET << std::endl;
     std::cout << "Debug mode: " << (debug_mode ? Color::GREEN + std::string("Enabled") : 
                                                  Color::YELLOW + std::string("Disabled")) 
                               << Color::RESET << std::endl;
     std::cout << "Valid ports: ";
     for (size_t i = 0; i < VALID_PORTS.size(); ++i) {
         std::cout << VALID_PORTS[i];
         if (i < VALID_PORTS.size() - 1) std::cout << ", ";
     }
     std::cout << std::endl;
     std::cout << "POW threads: " << POW_THREAD_COUNT << std::endl << std::endl;
     
     try {
         // Set up user information
         ExatestClient::UserInfo userInfo;
         
         // Add your actual information here
         userInfo.name = "Your Full Name";
         userInfo.emails = {"your.email@example.com", "secondary.email@example.com"};
         userInfo.skype = "your.skype";
         userInfo.birthdate = "01.01.1990"; // Format: DD.MM.YYYY
         userInfo.country = "Germany"; // Use a valid country name
         userInfo.addressLines = {"Street Name 123", "12345 City"};
         
         // Certificates from the readme file
         std::string cert = 
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
         
         std::string key = 
             "-----BEGIN EC PRIVATE KEY-----\n"
             "MHcCAQEEIO1eB3IU8m/qEpWdMShCR++gZGHTjmz7MWfnEgyrvessoAoGCCqGSM49\n"
             "AwEHoUQDQgAE0WNjxYaOBrXjoBS4yulCFkjI8093T9vRq1ve5tzuYqAcqsO1qSbL\n"
             "Q3TXlSFGUDmT91WTdFt6RZk50IxRqM5YhA==\n"
             "-----END EC PRIVATE KEY-----\n";
         
         // Create the client
         ExatestClient client(SERVER_HOSTNAME, cert, key, userInfo);
         
         logger.header("Connecting to " + SERVER_HOSTNAME);
         
         if (!client.connect()) {
             logger.error("Failed to establish connection to " + SERVER_HOSTNAME);
             WSACleanup(); // Clean up Winsock
             return 1;
         }
         
         logger.header("Executing Protocol Sequence");
         
         if (!client.runProtocol()) {
             logger.error("Protocol execution failed");
             client.disconnect();
             WSACleanup(); // Clean up Winsock
             return 1;
         }
         
         logger.header("Protocol Sequence Completed Successfully");
         logger.success("All commands processed and END received");
         
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