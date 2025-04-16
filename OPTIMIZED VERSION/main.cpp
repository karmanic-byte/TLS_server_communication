#include <iostream>
#include <string>
#include <chrono>
#include <winsock2.h>
#include "utils.h"
#include "logger.h"
#include "config.h"
#include "pow_solver.h"
#include "tls_connection.h"
#include "exatest_client.h"

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