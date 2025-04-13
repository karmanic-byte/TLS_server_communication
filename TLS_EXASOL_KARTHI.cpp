/*
 * Implementation of the exercise program in C++
 * This program connects to a server via TLS, completes a proof-of-work challenge,
 * and submits personal information according to server requests.
 */

 #include <iostream>
 #include <string>
 #include <vector>
 #include <random>
 #include <sstream>
 #include <iomanip>
 #include <chrono>
 #include <thread>
 #include <stdexcept>
 #include <fstream>  // For std::ofstream
#include <cstdio>   // For std::remove
#include <cstring>  // For string manipulation functions
 
 // OpenSSL headers for TLS connection and SHA1 hashing
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 #include <openssl/sha.h>
 
 // Constants
 constexpr const char* SERVER_ADDRESS = " 18.202.148.138";
 constexpr int SERVER_PORT = 3336;
 constexpr const char* CERT_FILE = "client_cert.pem";
 constexpr const char* KEY_FILE = "client_key.pem";
 
 // Function to initialize OpenSSL and create a TLS connection
 SSL* tls_connect(const std::string& server, const std::string& cert_file, const std::string& key_file) {
     // Initialize OpenSSL
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
// OpenSSL 3.0 or newer
OPENSSL_init_ssl(0, NULL);
#else
// Older versions
SSL_library_init();
OpenSSL_add_all_algorithms();
SSL_load_error_strings();
ERR_load_BIO_strings();
#endif
     
     // Create SSL context
     SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
     if (!ctx) {
         std::cerr << "Error creating SSL context" << std::endl;
         ERR_print_errors_fp(stderr);
         return nullptr;
     }
     
     // Load the client certificate and private key
     if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
         std::cerr << "Error loading certificate file" << std::endl;
         ERR_print_errors_fp(stderr);
         SSL_CTX_free(ctx);
         return nullptr;
     }
     
     if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
         std::cerr << "Error loading private key file" << std::endl;
         ERR_print_errors_fp(stderr);
         SSL_CTX_free(ctx);
         return nullptr;
     }
     
     // Check if the private key matches the certificate
     if (!SSL_CTX_check_private_key(ctx)) {
         std::cerr << "Private key does not match the certificate" << std::endl;
         SSL_CTX_free(ctx);
         return nullptr;
     }
     
     // Parse server address and port
     std::string host = server.substr(0, server.find(':'));
     int port = std::stoi(server.substr(server.find(':') + 1));
     
     // Create a BIO object for socket connection
     BIO* bio = BIO_new_connect((host + ":" + std::to_string(port)).c_str());
     if (!bio) {
         std::cerr << "Error creating connection BIO" << std::endl;
         ERR_print_errors_fp(stderr);
         SSL_CTX_free(ctx);
         return nullptr;
     }
     
     // Connect to the server
     if (BIO_do_connect(bio) <= 0) {
         std::cerr << "Error connecting to server" << std::endl;
         ERR_print_errors_fp(stderr);
         BIO_free_all(bio);
         SSL_CTX_free(ctx);
         return nullptr;
     }
     
     // Create SSL object and attach it to the connection
     SSL* ssl = SSL_new(ctx);
     if (!ssl) {
         std::cerr << "Error creating SSL object" << std::endl;
         ERR_print_errors_fp(stderr);
         BIO_free_all(bio);
         SSL_CTX_free(ctx);
         return nullptr;
     }
     
     SSL_set_bio(ssl, bio, bio);
     
     // Perform SSL handshake
     if (SSL_connect(ssl) <= 0) {
         std::cerr << "Error performing SSL handshake" << std::endl;
         ERR_print_errors_fp(stderr);
         SSL_free(ssl);
         SSL_CTX_free(ctx);
         return nullptr;
     }
     
     std::cout << "Successfully established TLS connection to " << server << std::endl;
     return ssl;
 }
 
 // Function to read a line from the SSL connection
 std::string ssl_read_line(SSL* ssl) {
     std::string line;
     char buffer[1];
     int bytes_read;
     
     while (true) {
         bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
         
         if (bytes_read <= 0) {
             int err = SSL_get_error(ssl, bytes_read);
             if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                 // Non-blocking operation in progress, try again
                 std::this_thread::sleep_for(std::chrono::milliseconds(10));
                 continue;
             } else {
                 throw std::runtime_error("Error reading from SSL connection");
             }
         }
         
         if (buffer[0] == '\n') {
             break;
         }
         
         line += buffer[0];
     }
     
     return line;
 }
 
 // Function to write a string to the SSL connection
 void ssl_write(SSL* ssl, const std::string& data) {
     int bytes_written = SSL_write(ssl, data.c_str(), data.length());
     
     if (bytes_written <= 0) {
         int err = SSL_get_error(ssl, bytes_written);
         if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
             // Non-blocking operation in progress, try again
             std::this_thread::sleep_for(std::chrono::milliseconds(10));
             ssl_write(ssl, data);  // Recursive call to try again
         } else {
             throw std::runtime_error("Error writing to SSL connection");
         }
     }
     
     std::cout << "Sent: " << data;
 }
 
 // Function to calculate SHA1 hash of a string
 std::string sha1(const std::string& input) {
     unsigned char hash[SHA_DIGEST_LENGTH];
     SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
     
     std::stringstream ss;
     for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
         ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
     }
     
     return ss.str();
 }
 
 // Function to generate a random string for the POW challenge
 // Avoiding newline, carriage return, tab, and space characters
 std::string random_string(size_t length = 8) {
     static const std::string charset = 
         "abcdefghijklmnopqrstuvwxyz"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
         "0123456789"
         "!@#$%^&*()-_=+[]{}|;:,.<>?";
     
     std::random_device rd;
     std::mt19937 generator(rd());
     std::uniform_int_distribution<int> distribution(0, charset.length() - 1);
     
     std::string result;
     result.reserve(length);
     
     for (size_t i = 0; i < length; ++i) {
         result += charset[distribution(generator)];
     }
     
     return result;
 }
 
 // Split a string by space character
 std::vector<std::string> split(const std::string& str) {
     std::vector<std::string> tokens;
     std::stringstream ss(str);
     std::string token;
     
     while (ss >> token) {
         tokens.push_back(token);
     }
     
     return tokens;
 }
 
// Add this function to your original code to enable local testing without a TLS connection

// Function to test the program logic locally without TLS connection
int main_test() {
    std::string authdata = "";
    
    while (true) {
        // Read a command from stdin instead of SSL
        std::cout << "Enter server command: ";
        std::string line;
        std::getline(std::cin, line);
        std::cout << "Received: " << line << std::endl;
        
        // Parse the command and arguments
        std::vector<std::string> args = split(line);
        
        if (args.empty()) {
            continue;
        }
        
        const std::string& command = args[0];
        
        // Process the command
        if (command == "HELO") {
            // Initial handshake
            std::cout << "Sent: EHLO\n";
        } 
        else if (command == "ERROR") {
            // Error occurred, print message and break
            std::cerr << "ERROR: ";
            for (size_t i = 1; i < args.size(); ++i) {
                std::cerr << args[i] << " ";
            }
            std::cerr << std::endl;
            break;
        } 
        else if (command == "POW") {
            // Proof of Work challenge
            authdata = args[1];
            int difficulty = std::stoi(args[2]);
            std::cout << "POW challenge: authdata=" << authdata 
                      << ", difficulty=" << difficulty << std::endl;
            
            // Solve the POW challenge
            while (true) {
                std::string suffix = random_string();
                std::string combined = authdata + suffix;
                std::string cksum_in_hex = sha1(combined);
                
                // Check if the hash has the required number of leading zeros
                bool valid = true;
                for (int i = 0; i < difficulty; ++i) {
                    if (cksum_in_hex[i] != '0') {
                        valid = false;
                        break;
                    }
                }
                
                if (valid) {
                    std::cout << "Found valid POW solution: " << suffix << std::endl;
                    std::cout << "Hash: " << cksum_in_hex << std::endl;
                    std::cout << "Sent: " << suffix << "\n";
                    break;
                }
            }
        } 
        else if (command == "END") {
            // End of communication, data was submitted successfully
            std::cout << "Sent: OK\n";
            std::cout << "Data submitted successfully!" << std::endl;
            break;
        } 
        else if (command == "NAME") {
            // Respond with user's full name
            std::string response = sha1(authdata + args[1]) + " " + "John Doe";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "MAILNUM") {
            // Respond with the number of email addresses
            std::string response = sha1(authdata + args[1]) + " " + "2";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "MAIL1") {
            // Respond with the first email address
            std::string response = sha1(authdata + args[1]) + " " + "john.doe@example.com";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "MAIL2") {
            // Respond with the second email address
            std::string response = sha1(authdata + args[1]) + " " + "john.doe2@example.com";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "SKYPE") {
            // Respond with Skype username or N/A
            std::string response = sha1(authdata + args[1]) + " " + "john.doe";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "BIRTHDATE") {
            // Respond with birthdate in format DD.MM.YYYY
            std::string response = sha1(authdata + args[1]) + " " + "01.01.1990";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "COUNTRY") {
            // Respond with country of residence
            std::string response = sha1(authdata + args[1]) + " " + "Germany";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "ADDRNUM") {
            // Respond with number of address lines
            std::string response = sha1(authdata + args[1]) + " " + "2";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "ADDRLINE1") {
            // Respond with address line 1
            std::string response = sha1(authdata + args[1]) + " " + "Hauptstrasse 123";
            std::cout << "Sent: " << response << "\n";
        } 
        else if (command == "ADDRLINE2") {
            // Respond with address line 2
            std::string response = sha1(authdata + args[1]) + " " + "10115 Berlin";
            std::cout << "Sent: " << response << "\n";
        } 
        else {
            std::cerr << "Unknown command: " << command << std::endl;
        }
    }
    
    return 0;
}



 int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--test") {
        return main_test();  // Run in test mode
    }
    
    try {
        // Extract certificates and keys to files
        std::ofstream cert_file(CERT_FILE);
        cert_file << R"(-----BEGIN CERTIFICATE-----
MIIBIzCBywIBATAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBleGF0ZXN0LmR5bnUu
bmV0MB4XDTI1MDQwNzEwMDQzMloXDTI1MDQyMjEwMDQzMlowIjEgMB4GA1UEAwwX
Y2xpZW50LmV4YXRlc3QuZHludS5uZXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATRY2PFho4GteOgFLjK6UIWSMjzT3dP29GrW97m3O5ioByqw7WpJstDdNeVIUZQ
OZP3VZN0W3pFmTnQjFGozliEMAoGCCqGSM49BAMCA0cAMEQCIAqmlL3y7mtbx6MS
LgWmr59iLFo+cuAfXUyB7tei5SoeAiALcj5St2c7rUlnaS2TIe+7qhhIVD4wayeO
DjRturJDbg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBJTCBzAIJAIHpTe1vt7jeMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEGV4YXRl
c3QuZHludS5uZXQwHhcNMjIwNjE3MTE0MTM2WhcNMjYwNjE2MTE0MTM2WjAbMRkw
FwYDVQQDDBBleGF0ZXN0LmR5bnUubmV0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEd7kDTSuNxx6xcYD1uOi89rjsMuarCIq1PnskB2Oy5QyxL/kYF9Sqc2oIfmSq
SXMh+6sFy11s5aNcMsYoMKzewjAKBggqhkjOPQQDAgNIADBFAiEAktlnw4xaDstX
rmu2MT01AoJqOknfvu/PRysvRj+BZkwCIGiGG312KhvHY7ajJlKet3dnZeNsga6A
LbFlgfAzHy2a
-----END CERTIFICATE-----)";
        cert_file.close();

        std::ofstream key_file(KEY_FILE);
        key_file << R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIO1eB3IU8m/qEpWdMShCR++gZGHTjmz7MWfnEgyrvessoAoGCCqGSM49
AwEHoUQDQgAE0WNjxYaOBrXjoBS4yulCFkjI8093T9vRq1ve5tzuYqAcqsO1qSbL
Q3TXlSFGUDmT91WTdFt6RZk50IxRqM5YhA==
-----END EC PRIVATE KEY-----)";
        key_file.close();

        // Connect to the server
        std::string server_address = std::string(SERVER_ADDRESS) + ":" + std::to_string(SERVER_PORT);
        SSL* ssl = tls_connect(server_address, CERT_FILE, KEY_FILE);
        
        if (!ssl) {
            std::cerr << "Failed to establish TLS connection" << std::endl;
            return 1;
        }
        
        // Main interaction loop
        std::string authdata = "";
        
        // ... rest of the original main function ...
        
        // Clean up
        SSL_shutdown(ssl);
        SSL_free(ssl);
        
        // Clean up temporary files
        std::remove(CERT_FILE);
        std::remove(KEY_FILE);
        
        return 0;
    } 
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
}