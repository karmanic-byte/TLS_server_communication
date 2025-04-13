/**
 * TLS Client Communication with OpenSSL
 * 
 * This program establishes a TLS connection to a server and handles secure communications.
 * It includes proper error handling, resource cleanup, and parallel processing capabilities.
 * 
 * Compilation: 
 * g++ -Wall -Wextra -g3 TLS_EXASOL_KARTHI.cpp -o TLS_EXASOL_KARTHI.exe -lssl -lcrypto -lpthread
 * 
 * Note: Make sure OpenSSL development libraries are installed on your system.
 * For MSYS2/MinGW: pacman -S mingw-w64-ucrt-x86_64-openssl
 */

 #include <iostream>
 #include <sstream>
 #include <string>
 #include <vector>
 #include <mutex>
 #include <thread>
 #include <chrono>
 #include <atomic>
 #include <queue>
 #include <condition_variable>
 #include <memory>
 #include <fstream>
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 #include <openssl/bio.h>
 #include <openssl/sha.h>
 
 // Logger class for debug messages with different log levels
 class Logger {
 public:
     enum LogLevel {
         DEBUG=1,
         INFO,
         WARNING,
         /// @brief Error handling
     };
 
     
     Logger(LogLevel level = INFO, std::ostream& output = std::cout) 
         : m_level(level), m_output(output) {}
 
     template<typename... Args>
     void debug(const std::string& format, Args... args) {
         if (m_level <= DEBUG) {
             log("DEBUG", format, args...);
         }
     }
 
     template<typename... Args>
     void info(const std::string& format, Args... args) {
         if (m_level <= INFO) {
             log("INFO", format, args...);
         }
     }
 
     template<typename... Args>
     void warning(const std::string& format, Args... args) {
         if (m_level <= WARNING) {
             log("WARNING", format, args...);
         }
     }
 
     template<typename... Args>
     void error(const std::string& format, Args... args) {
         if (m_level <= ERROR) {
             log("ERROR", format, args...);
         }
     }
 
     void setLogLevel(LogLevel level) {
         m_level = level;
     }
 
 private:
     LogLevel m_level;
     std::ostream& m_output;
     std::mutex m_mutex;
 
     template<typename... Args>
     void log(const std::string& level, const std::string& format, Args... args) {
         std::lock_guard<std::mutex> lock(m_mutex);
         auto now = std::chrono::system_clock::now();
         auto time = std::chrono::system_clock::to_time_t(now);
         
         char timeStr[20];
         std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
         
         m_output << "[" << timeStr << "][" << level << "] ";
         
         // Simple formatting (not as powerful as printf but works for basic cases)
         //size_t pos = 0;
         if constexpr(sizeof...(Args) > 0) {
            size_t pos = 0;
            std::string formatted = format;
            ((replace_placeholder(formatted, pos, args)), ...); 

            m_output << formatted << std::endl;
        }
         
         
     }
 
     template<typename T>
     void replace_placeholder(std::string& str, size_t& pos, T value) {
         size_t placeholder = str.find("{}", pos);
         if (placeholder != std::string::npos) {
             std::ostringstream oss;
             oss << value;
             str.replace(placeholder, 2, oss.str());
             pos = placeholder + oss.str().length();
         }
     }
 };
 
 // Global logger instance
 Logger logger(Logger::DEBUG);
 
 // Thread-safe task queue for worker threads
 template<typename T>
 class TaskQueue {
 public:
     void push(T item) {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_queue.push(item);
         lock.unlock();
         m_condition.notify_one();
     }
 
     bool pop(T& item) {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_condition.wait(lock, [this] { return !m_queue.empty() || m_stop; });
         
         if (m_queue.empty()) {
             return false;
         }
         
         item = m_queue.front();
         m_queue.pop();
         return true;
     }
 
     void stop() {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_stop = true;
         lock.unlock();
         m_condition.notify_all();
     }
 
     bool empty() {
         std::unique_lock<std::mutex> lock(m_mutex);
         return m_queue.empty();
     }
 
     size_t size() {
         std::unique_lock<std::mutex> lock(m_mutex);
         return m_queue.size();
     }
 
 private:
     std::queue<T> m_queue;
     std::mutex m_mutex;
     std::condition_variable m_condition;
     bool m_stop = false;
 };
 
 // Class to hold TLS connection and provide communication methods
 class TLSConnection {
 public:
     TLSConnection() : m_ssl(nullptr), m_ctx(nullptr), m_connected(false) {}
     
     ~TLSConnection() {
         disconnect();
     }
 
     bool connect(const std::string& hostname, const std::string& cert_file, const std::string& key_file, int port = 443) {
         logger.info("Connecting to {} on port {}", hostname, port);
         
         // Initialize OpenSSL
         if (!initialize_openssl()) {
             return false;
         }
         
         // Create a new SSL context
         m_ctx = SSL_CTX_new(TLS_client_method());
         if (!m_ctx) {
             logger.error("Unable to create SSL context");
             print_ssl_errors();
             return false;
         }
         
         // Load certificate if provided
         if (!cert_file.empty()) {
             if (SSL_CTX_use_certificate_file(m_ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
                 logger.error("Failed to load certificate: {}", cert_file);
                 print_ssl_errors();
                 SSL_CTX_free(m_ctx);
                 m_ctx = nullptr;
                 return false;
             }
             logger.debug("Certificate loaded successfully");
         }
         
         // Load private key if provided
         if (!key_file.empty()) {
             if (SSL_CTX_use_PrivateKey_file(m_ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
                 logger.error("Failed to load private key: {}", key_file);
                 print_ssl_errors();
                 SSL_CTX_free(m_ctx);
                 m_ctx = nullptr;
                 return false;
             }
             
             // Check private key
             if (!SSL_CTX_check_private_key(m_ctx)) {
                 logger.error("Private key does not match the certificate");
                 print_ssl_errors();
                 SSL_CTX_free(m_ctx);
                 m_ctx = nullptr;
                 return false;
             }
             logger.debug("Private key loaded successfully");
         }
         
         // Create BIO connection
         std::string connect_str = hostname + ":" + std::to_string(port);
         BIO* bio = BIO_new_connect(connect_str.c_str());
         if (!bio) {
             logger.error("Failed to create connection BIO");
             print_ssl_errors();
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         // Attempt to connect
         if (BIO_do_connect(bio) <= 0) {
             logger.error("Failed to connect to {}:{}", hostname, port);
             print_ssl_errors();
             BIO_free_all(bio);
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         logger.info("TCP Connection established");
         
         // Create new SSL structure
         m_ssl = SSL_new(m_ctx);
         if (!m_ssl) {
             logger.error("Failed to create SSL structure");
             print_ssl_errors();
             BIO_free_all(bio);
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         // Connect the SSL object to the BIO
         SSL_set_bio(m_ssl, bio, bio);
         
         // Perform TLS handshake
         if (SSL_connect(m_ssl) <= 0) {
             logger.error("SSL handshake failed");
             print_ssl_errors();
             SSL_free(m_ssl);
             m_ssl = nullptr;
             SSL_CTX_free(m_ctx);
             m_ctx = nullptr;
             return false;
         }
         
         logger.info("SSL handshake successful. Using {}", SSL_get_cipher(m_ssl));
         logger.debug("Server certificate:");
         X509* cert = SSL_get_peer_certificate(m_ssl);
         if (cert) {
             char* line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
             logger.debug("Subject: {}", line);
             OPENSSL_free(line);
             
             line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
             logger.debug("Issuer: {}", line);
             OPENSSL_free(line);
             
             X509_free(cert);
         } else {
             logger.warning("No server certificate received");
         }
         
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
         logger.info("TLS Connection closed");
     }
     
     bool is_connected() const {
         return m_connected;
     }
     
     std::string read_line() {
         if (!m_ssl || !m_connected) {
             logger.error("Attempted to read from disconnected SSL");
             return "";
         }
         
         std::string line;
         char buf[1024];
         int bytes;
         
         while (true) {
             bytes = SSL_read(m_ssl, buf, sizeof(buf) - 1);
             
             if (bytes <= 0) {
                 int err = SSL_get_error(m_ssl, bytes);
                 if (err == SSL_ERROR_ZERO_RETURN) {
                     logger.info("SSL connection closed by peer");
                     m_connected = false;
                 } else {
                     logger.error("SSL read error: {}", err);
                     print_ssl_errors();
                 }
                 break;
             }
             
             buf[bytes] = '\0';
             line.append(buf);
             
             // If we've found a newline, we're done
             if (line.find('\n') != std::string::npos) {
                 break;
             }
         }
         
         // Trim trailing newline if present
         if (!line.empty() && line.back() == '\n') {
             line.pop_back();
         }
         
         return line;
     }
     
     bool write(const std::string& data) {
         if (!m_ssl || !m_connected) {
             logger.error("Attempted to write to disconnected SSL");
             return false;
         }
         
         int bytes = SSL_write(m_ssl, data.c_str(), static_cast<int>(data.length()));
         
         if (bytes <= 0) {
             int err = SSL_get_error(m_ssl, bytes);
             logger.error("SSL write error: {}", err);
             print_ssl_errors();
             return false;
         }
         
         return true;
     }
     
     // Helper function to compute SHA-1 hash
     static std::string sha1(const std::string& input) {
         unsigned char hash[SHA_DIGEST_LENGTH];
         SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
         
         std::string output;
         char hex[3];
         for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
             sprintf(hex, "%02x", hash[i]);
             output.append(hex);
         }
         
         return output;
     }
 
 private:
     SSL* m_ssl;
     SSL_CTX* m_ctx;
     bool m_connected;
     
     bool initialize_openssl() {
         // Initialize the OpenSSL library
         if (OPENSSL_init_ssl(0, NULL) == 0) {
             logger.error("Failed to initialize OpenSSL library");
             print_ssl_errors();
             return false;
         }
         
         return true;
     }
     
     void print_ssl_errors() {
         unsigned long err;
         char err_buf[256];
         
         while ((err = ERR_get_error()) != 0) {
             ERR_error_string_n(err, err_buf, sizeof(err_buf));
             logger.error("SSL error: {}", err_buf);
         }
     }
 };
 
 // Worker class for parallel TLS connections
 class TLSWorker {
 public:
     TLSWorker(const std::string& hostname, 
              const std::string& cert_file, 
              const std::string& key_file, 
              int port,
              TaskQueue<std::string>& task_queue,
              TaskQueue<std::string>& result_queue)
         : m_hostname(hostname),
           m_cert_file(cert_file),
           m_key_file(key_file),
           m_port(port),
           m_task_queue(task_queue),
           m_result_queue(result_queue),
           m_running(false) {}
     
     void start() {
         m_running = true;
         m_thread = std::thread(&TLSWorker::worker_loop, this);
     }
     
     void stop() {
         m_running = false;
         if (m_thread.joinable()) {
             m_thread.join();
         }
     }
     
     bool is_running() const {
         return m_running;
     }
     
 private:
     std::string m_hostname;
     std::string m_cert_file;
     std::string m_key_file;
     int m_port;
     TaskQueue<std::string>& m_task_queue;
     TaskQueue<std::string>& m_result_queue;
     std::atomic<bool> m_running;
     std::thread m_thread;
     
     void worker_loop() {
         logger.info("Worker thread started");
         
         // Create TLS connection
         TLSConnection connection;
         if (!connection.connect(m_hostname, m_cert_file, m_key_file, m_port)) {
             logger.error("Worker failed to establish TLS connection");
             m_running = false;
             return;
         }
         
         // Process tasks until stopped
         while (m_running) {
             std::string task;
             if (!m_task_queue.pop(task)) {
                 break;  // Queue is empty and stop has been called
             }
             
             logger.debug("Worker processing task: {}", task);
             
             // Write the task to the server
             if (!connection.write(task + "\n")) {
                 logger.error("Failed to send task to server");
                 continue;
             }
             
             // Read the response
             std::string response = connection.read_line();
             if (!response.empty()) {
                 logger.debug("Worker received response (length {})", response.length());
                 m_result_queue.push(response);
             }
         }
         
         // Clean up
         connection.disconnect();
         logger.info("Worker thread stopped");
     }
 };
 
 // TLS Client class with parallel worker support
 class TLSClient {
 public:
     TLSClient(const std::string& hostname, 
              const std::string& cert_file, 
              const std::string& key_file, 
              int port = 443,
              int num_workers = std::thread::hardware_concurrency())
         : m_hostname(hostname),
           m_cert_file(cert_file),
           m_key_file(key_file),
           m_port(port),
           m_num_workers(num_workers) {}
     
     ~TLSClient() {
         stop();
     }
     
     bool start() {
         logger.info("Starting TLS client with {} workers", m_num_workers);
         
         if (m_workers.size() > 0) {
             logger.warning("TLS client already started");
             return false;
         }
         
         // Create and start workers
         for (int i = 0; i < m_num_workers; i++) {
             std::unique_ptr<TLSWorker> worker = std::make_unique<TLSWorker>(
                 m_hostname, m_cert_file, m_key_file, m_port, m_task_queue, m_result_queue);
             
             worker->start();
             m_workers.push_back(std::move(worker));
         }
         
         return true;
     }
     
     void stop() {
         logger.info("Stopping TLS client");
         
         // Signal all workers to stop
         m_task_queue.stop();
         
         // Wait for all workers to finish
         for (auto& worker : m_workers) {
             worker->stop();
         }
         
         // Clear workers
         m_workers.clear();
     }
     
     void submit_task(const std::string& task) {
         if (m_workers.empty()) {
             logger.error("Cannot submit task - TLS client not started");
             return;
         }
         
         logger.debug("Submitting task: {}", task);
         m_task_queue.push(task);
     }
     
     std::string get_result() {
         std::string result;
         if (m_result_queue.pop(result)) {
             return result;
         }
         return "";
     }
     
     bool has_results() {
         return !m_result_queue.empty();
     }
     
     size_t pending_task_count() {
         return m_task_queue.size();
     }
     
     size_t result_count() {
         return m_result_queue.size();
     }
     
     bool all_workers_running() {
         for (const auto& worker : m_workers) {
             if (!worker->is_running()) {
                 return false;
             }
         }
         return !m_workers.empty();
     }
 
 private:
     std::string m_hostname;
     std::string m_cert_file;
     std::string m_key_file;
     int m_port;
     int m_num_workers;
     
     TaskQueue<std::string> m_task_queue;
     TaskQueue<std::string> m_result_queue;
     std::vector<std::unique_ptr<TLSWorker>> m_workers;
 };
 
 // Example usage
 int main(int argc, char* argv[]) {
     // Parse command-line arguments
     std::string hostname = "18.202.148.130";           
     std::string cert_file = "";
     std::string key_file = "";
     int port = 443;
     int num_workers = std::thread::hardware_concurrency();
     
     for (int i = 1; i < argc; i++) {
         std::string arg = argv[i];
         
         if (arg == "--host" && i + 1 < argc) {
             hostname = argv[++i];
         } else if (arg == "--cert" && i + 1 < argc) {
             cert_file = argv[++i];
         } else if (arg == "--key" && i + 1 < argc) {
             key_file = argv[++i];
         } else if (arg == "--port" && i + 1 < argc) {
             port = std::stoi(argv[++i]);
         } else if (arg == "--workers" && i + 1 < argc) {
             num_workers = std::stoi(argv[++i]);
         } else if (arg == "--debug") {
             logger.setLogLevel(Logger::DEBUG);
         } else if (arg == "--help") {
             std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
             std::cout << "Options:" << std::endl;
             std::cout << "  --host HOST      Server hostname (default: example.com)" << std::endl;
             std::cout << "  --cert FILE      Certificate file in PEM format" << std::endl;
             std::cout << "  --key FILE       Private key file in PEM format" << std::endl;
             std::cout << "  --port PORT      Server port (default: 443)" << std::endl;
             std::cout << "  --workers NUM    Number of worker threads (default: auto)" << std::endl;
             std::cout << "  --debug          Enable debug logging" << std::endl;
             std::cout << "  --help           Show this help message" << std::endl;
             return 0;
         }
     }
     
     logger.info("TLS Client starting up");
     logger.info("Host: {}, Port: {}", hostname, port);
     logger.info("Certificate: {}", cert_file.empty() ? "None" : cert_file);
     logger.info("Private Key: {}", key_file.empty() ? "None" : key_file);
     logger.info("Worker Threads: {}", num_workers);
     
     // Create client
     TLSClient client(hostname, cert_file, key_file, port, num_workers);
     
     // Start the client
     if (!client.start()) {
         logger.error("Failed to start TLS client");
         return 1;
     }
     
     // Example tasks (in a real application, these would come from elsewhere)
     std::vector<std::string> tasks = {
         "GET / HTTP/1.1",
         "Host: " + hostname,
         "Connection: close",
         ""
     };
     
     // Submit tasks
     for (const auto& task : tasks) {
         client.submit_task(task);
         logger.debug("Submitted: {}", task);
     }
     
     // Wait for and process results
     std::this_thread::sleep_for(std::chrono::seconds(2));
     
     logger.info("Received {} results", client.result_count());
     
     while (client.has_results()) {
         std::string result = client.get_result();
         logger.info("Result: {}", result);
     }
     
     // Stop the client
     client.stop();
     logger.info("TLS Client shutdown complete");
     
     return 0;
 }