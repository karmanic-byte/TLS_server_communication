#ifndef TLS_CONNECTION_H
#define TLS_CONNECTION_H

#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "utils.h"
#include "logger.h"

// Enhanced TLS Connection class with improved error handling and diagnostics
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
        
        // Get and log certificate information
        logCertificateInfo();
        
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
    
    std::string readLine(int timeout_seconds = 6) {
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
    
    void logCertificateInfo() {
        if (!m_ssl) return;
        
        X509* cert = SSL_get_peer_certificate(m_ssl);
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