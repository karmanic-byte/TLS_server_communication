#ifndef TLS_CONNECTION_H
#define TLS_CONNECTION_H

#include <string>
#include <memory>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/time.h>
#include <errno.h>
#endif

#include "utils.h"
#include "logger.h"

// Smart pointer cleanup handlers for OpenSSL
struct SslDeleter {
    void operator()(SSL* ssl) {
        if (ssl) SSL_free(ssl);
    }
};

struct SslCtxDeleter {
    void operator()(SSL_CTX* ctx) {
        if (ctx) SSL_CTX_free(ctx);
    }
};

struct BioDeleter {
    void operator()(BIO* bio) {
        if (bio) BIO_free_all(bio);
    }
};

// Enhanced TLS Connection class with RAII and improved error handling
class TLSConnection {
public:
    TLSConnection() : m_connected(false), m_socket(-1) {
        // Initialize network subsystem if needed
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            logger.error("Failed to initialize Winsock");
        }
#endif
    }
    
    ~TLSConnection() {
        disconnect();
        
#ifdef _WIN32
        // Clean up Winsock
        WSACleanup();
#endif
    }
    
    bool connect(const std::string& hostname, int port, const std::string& certFile, const std::string& keyFile) {
        logger.info("Connecting to " + hostname + ":" + std::to_string(port));
        
        // Initialize OpenSSL
        if (!initializeSSL()) {
            return false;
        }
        
        // Create a new SSL context
        m_ctx.reset(SSL_CTX_new(TLS_client_method()));
        if (!m_ctx) {
            logger.error("Failed to create SSL context");
            printSSLErrors();
            return false;
        }
        
        // Set up context options
        SSL_CTX_set_options(m_ctx.get(), SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_mode(m_ctx.get(), SSL_MODE_AUTO_RETRY);
        
        // Load certificate and key
        if (!loadCertificates(certFile, keyFile)) {
            return false;
        }
        
        // Resolve hostname
        // Use this fully initialized struct:
struct addrinfo hints;
memset(&hints, 0, sizeof(hints));
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
struct addrinfo *addr_result = nullptr;

        
        std::string portStr = std::to_string(port);
        int gai_result = getaddrinfo(hostname.c_str(), portStr.c_str(), &hints, &addr_result);

        if (gai_result != 0) {
#ifdef _WIN32
            logger.error("Failed to resolve hostname: " + std::to_string(WSAGetLastError()));
#else
            logger.error("Failed to resolve hostname: " + std::string(gai_strerror(gai_result)));
#endif
            return false;
        }
        
        // Try each address until we successfully connect
        bool connected = false;
        for (struct addrinfo* rp = addr_result; rp != nullptr; rp = rp->ai_next) {
            // Create socket
#ifdef _WIN32
            m_socket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (m_socket == INVALID_SOCKET) {
                continue;
            }
#else
            m_socket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (m_socket == -1) {
                continue;
            }
#endif
            
            // Set socket to non-blocking mode for connection with timeout
#ifdef _WIN32
            u_long mode = 1; // 1 = non-blocking
            ioctlsocket(m_socket, FIONBIO, &mode);
#else
            int flags = fcntl(m_socket, F_GETFL, 0);
            fcntl(m_socket, F_SETFL, flags | O_NONBLOCK);
#endif
            
            // Attempt to connect
            logger.debug("Initiating TCP connection");
#ifdef _WIN32
            int connect_result = ::connect(m_socket, rp->ai_addr, rp->ai_addrlen);
            if (connect_result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(m_socket);
                m_socket = INVALID_SOCKET;
                continue;
            }
#else
            int connect_result = ::connect(m_socket, rp->ai_addr, rp->ai_addrlen);
            if (connect_result == -1 && errno != EINPROGRESS) {
                close(m_socket);
                m_socket = -1;
                continue;
            }
#endif
            
            // Wait for connection with timeout
#ifdef _WIN32
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(m_socket, &write_fds);
            
            struct timeval timeout;
            timeout.tv_sec = 10;  // 10 second connection timeout
            timeout.tv_usec = 0;
            
            int select_result = select(0, NULL, &write_fds, NULL, &timeout);
            if (select_result <= 0) {
                closesocket(m_socket);
                m_socket = INVALID_SOCKET;
                continue;
            }
            
            // Check if the connection succeeded
            int error = 0;
            int len = sizeof(error);
            if (getsockopt(m_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &len) < 0 || error != 0) {
                closesocket(m_socket);
                m_socket = INVALID_SOCKET;
                continue;
            }
#else
            struct pollfd pfd;
            pfd.fd = m_socket;
            pfd.events = POLLOUT;
            
            int poll_result = poll(&pfd, 1, 10000); // 10 seconds timeout
            if (poll_result <= 0) {
                close(m_socket);
                m_socket = -1;
                continue;
            }
            
            // Check if the connection succeeded
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                close(m_socket);
                m_socket = -1;
                continue;
            }
#endif
            
            // Connection successful
            connected = true;
            break;
        }
        
        freeaddrinfo(addr_result);
        
        if (!connected) {
            logger.error("Failed to connect to " + hostname + ":" + std::to_string(port));
            return false;
        }
        
        logger.debug("TCP connection established");
        
        // Set socket back to blocking mode for TLS handshake
#ifdef _WIN32
        u_long mode = 0; // 0 = blocking
        ioctlsocket(m_socket, FIONBIO, &mode);
#else
        int flags = fcntl(m_socket, F_GETFL, 0);
        fcntl(m_socket, F_SETFL, flags & ~O_NONBLOCK);
#endif
        
        // Create BIO for the socket
        BIO* bio = BIO_new_socket(m_socket, BIO_NOCLOSE);
        if (!bio) {
            logger.error("Failed to create BIO for socket");
            printSSLErrors();
#ifdef _WIN32
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
#else
            close(m_socket);
            m_socket = -1;
#endif
            return false;
        }
        
        // Create SSL object
        m_ssl.reset(SSL_new(m_ctx.get()));
        if (!m_ssl) {
            logger.error("Failed to create SSL object");
            printSSLErrors();
            BIO_free(bio);
#ifdef _WIN32
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
#else
            close(m_socket);
            m_socket = -1;
#endif
            return false;
        }
        
        // Set hostname for SNI extension
        SSL_set_tlsext_host_name(m_ssl.get(), hostname.c_str());
        
        // Set up the SSL object with the BIO
        SSL_set_bio(m_ssl.get(), bio, bio);
        
        // Perform TLS handshake
        logger.debug("Starting TLS handshake");
        
        int ssl_result = SSL_connect(m_ssl.get());
        if (ssl_result != 1) {
            int ssl_error = SSL_get_error(m_ssl.get(), ssl_result);
            logger.error("TLS handshake failed with error: " + std::to_string(ssl_error));
            printSSLErrors();
            m_ssl.reset();
#ifdef _WIN32
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
#else
            close(m_socket);
            m_socket = -1;
#endif
            return false;
        }
        
        logger.success("TLS handshake completed successfully");
        logger.info("Using " + std::string(SSL_get_version(m_ssl.get())) + " with cipher " + 
                   std::string(SSL_get_cipher(m_ssl.get())));
        
        // Get and log certificate information
        logCertificateInfo();
        
        m_connected = true;
        return true;
    }
    
    void disconnect() {
        if (m_ssl) {
            SSL_shutdown(m_ssl.get());
            m_ssl.reset();
        }
        
        if (m_socket != static_cast<SOCKET>(-1))  {
#ifdef _WIN32
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
#else
            close(m_socket);
            m_socket = -1;
#endif
        }
        
        m_ctx.reset();
        m_connected = false;
        logger.info("Disconnected");
    }
    
    bool isConnected() const {
        return m_connected;
    }
    
    bool setReadTimeout(int seconds) {
        
        
#ifdef _WIN32
        // Set socket receive timeout (Windows version)
        if (m_socket == INVALID_SOCKET || !m_connected) return false;
        DWORD timeout = seconds * 1000; // convert to milliseconds
        if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
            logger.error("Failed to set read timeout: " + std::to_string(WSAGetLastError()));
            return false;
        }
#else
        // Set socket receive timeout (UNIX version)
        if (m_socket == -1 || !m_connected) return false;
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            logger.error("Failed to set read timeout: " + std::string(strerror(errno)));
            return false;
        }
#endif
        
        return true;
    }
    
    std::string readLine(int timeout_seconds = 6) {
        if (!m_ssl || !m_connected || m_socket == -1) {
            logger.error("Cannot read from closed connection");
            return "";
        }
        
        // Set socket timeout
        setReadTimeout(timeout_seconds);
        
        std::string line;
        char buffer[1];
        int bytes_read;
        
        auto start_time = std::chrono::steady_clock::now();
        
        while (true) {
            bytes_read = SSL_read(m_ssl.get(), buffer, 1);
            
            if (bytes_read > 0) {
                if (buffer[0] == '\n') {
                    break;
                }
                line += buffer[0];
            } else {
                int ssl_error = SSL_get_error(m_ssl.get(), bytes_read);
                
                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    // Connection closed
                    logger.debug("Connection closed by peer while reading");
                    m_connected = false;
                    break;
                } else if (ssl_error == SSL_ERROR_SYSCALL) {
                    // Check for timeout
#ifdef _WIN32
                    int wsaError = WSAGetLastError();
                    if (wsaError == WSAETIMEDOUT || wsaError == WSAEWOULDBLOCK) {
                        logger.error("Read timeout after " + std::to_string(timeout_seconds) + " seconds");
                    } else {
                        logger.error("Socket error during read: " + std::to_string(wsaError));
                    }
#else
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        logger.error("Read timeout after " + std::to_string(timeout_seconds) + " seconds");
                    } else {
                        logger.error("Socket error during read: " + std::string(strerror(errno)));
                    }
#endif
                    m_connected = false;
                    break;
                } else {
                    logger.error("SSL read error");
                    printSSLErrors();
                    m_connected = false;
                    break;
                }
            }
            
            // Check for overall timeout (in case the socket timeout doesn't work)
            auto current_time = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
            if (elapsed > timeout_seconds) {
                logger.error("Read operation timed out after " + std::to_string(elapsed) + " seconds");
                m_connected = false;
                break;
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
        if (!m_ssl || !m_connected || m_socket == -1) {
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
        int bytes_written = SSL_write(m_ssl.get(), data.c_str(), data.length());
        
        if (bytes_written <= 0) {
            int ssl_error = SSL_get_error(m_ssl.get(), bytes_written);
            
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
    std::unique_ptr<SSL_CTX, SslCtxDeleter> m_ctx;
    std::unique_ptr<SSL, SslDeleter> m_ssl;
    bool m_connected;
#ifdef _WIN32
    SOCKET m_socket;
#else
    int m_socket;
#endif
    
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
        if (SSL_CTX_use_certificate_file(m_ctx.get(), certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
            logger.error("Failed to load certificate file: " + certFile);
            printSSLErrors();
            return false;
        }
        
        // Load the private key
        if (SSL_CTX_use_PrivateKey_file(m_ctx.get(), keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
            logger.error("Failed to load private key file: " + keyFile);
            printSSLErrors();
            return false;
        }
        
        // Verify private key
        if (!SSL_CTX_check_private_key(m_ctx.get())) {
            logger.error("Private key does not match the certificate");
            printSSLErrors();
            return false;
        }
        
        logger.debug("Successfully loaded certificate and private key");
        return true;
    }
    
    void logCertificateInfo() {
        if (!m_ssl) return;
        
        X509* cert = SSL_get_peer_certificate(m_ssl.get());
        if (cert) {
            logger.debug("Server certificate information:");
            
            // Subject
            X509_NAME* subject = X509_get_subject_name(cert);
            char subjectStr[256];
            X509_NAME_oneline(subject, subjectStr, 256);
            logger.debug("  Subject: " + std::string(subjectStr));
            
            // Issuer
            X509_NAME* issuer = X509_get_issuer_name(cert);
            char issuerStr[256];
            X509_NAME_oneline(issuer, issuerStr, 256);
            logger.debug("  Issuer: " + std::string(issuerStr));
            
            // Validity
            ASN1_TIME* notBefore = X509_get_notBefore(cert);
            ASN1_TIME* notAfter = X509_get_notAfter(cert);
            
            BIO* bio = BIO_new(BIO_s_mem());
            char buffer[256];
            
            ASN1_TIME_print(bio, notBefore);
            int len = BIO_read(bio, buffer, sizeof(buffer) - 1);
            buffer[len] = '\0';
            logger.debug("  Valid from: " + std::string(buffer));
            
            BIO_reset(bio);
            ASN1_TIME_print(bio, notAfter);
            len = BIO_read(bio, buffer, sizeof(buffer) - 1);
            buffer[len] = '\0';
            logger.debug("  Valid until: " + std::string(buffer));
            
            BIO_free(bio);
            X509_free(cert);
        } else {
            logger.warning("No server certificate information available");
        }
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

#endif // TLS_CONNECTION_H