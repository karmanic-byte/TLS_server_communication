#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <random>
#include <algorithm>
#include <functional>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include "utils.h"
#include "logger.h"
#include "config.h"
#include "pow_solver.h"
#include "tls_connection.h"

#ifdef USE_OPENCL
#include "opencl_utils.h"
#endif

// User information struct
struct UserInfo {
    std::string name;
    std::vector<std::string> emails;
    std::string skype;
    std::string birthdate;
    std::string country;
    std::vector<std::string> addressLines;
    
    // Constructor with default values
    UserInfo() {
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
        
        std::cout << "Skype ID (or N/A if none): ";
        std::getline(std::cin, info.skype);
        
        // Validate and correct birthdate format
        bool validBirthdate = false;
        while (!validBirthdate) {
            std::cout << "Birthdate (DD.MM.YYYY): ";
            std::getline(std::cin, info.birthdate);
            
            if (info.birthdate.length() == 10 && 
                info.birthdate[2] == '.' && 
                info.birthdate[5] == '.') {
                validBirthdate = true;
            } else {
                std::cout << Color::RED << "Invalid birthdate format. Please use DD.MM.YYYY format." 
                          << Color::RESET << "\n";
            }
        }
        
        // Country selection with validation
        bool validCountry = false;
        while (!validCountry) {
            std::cout << "Country (from https://www.countries-ofthe-world.com/all-countries.html): ";
            std::getline(std::cin, info.country);
            
            validCountry = countryList.isValid(info.country);
            if (!validCountry) {
                std::cout << Color::RED << "Invalid country name. Please use a country name from the list." 
                          << Color::RESET << "\n";
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

// Main client class for the Exatest protocol
class ExatestClient {
public:
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
                std::string challengeStr, difficultyStr;
                iss >> challengeStr >> difficultyStr;
                
                if (challengeStr.empty() || difficultyStr.empty()) {
                    logger.error("Invalid POW challenge format: " + args);
                    return false;
                }
                
                authdata = challengeStr; // Save authdata for subsequent commands
                int difficulty = std::stoi(difficultyStr);
                
                logger.info("Received POW challenge - difficulty: " + difficultyStr);
                logger.info("Challenge: " + challengeStr);
                
                // Use our optimized POW solver
                logger.header("Starting Enhanced POW Solver");
                
                // Choose the optimal strategy based on configuration
                std::string strategy = "auto";
                if (config.powUseGPU) {
                    strategy = "gpu";
                } else if (config.powUseAdaptive) {
                    strategy = "adaptive";
                } else if (config.powUseHybrid) {
                    strategy = "hybrid";
                } else {
                    strategy = "cpu";
                }
                
                logger.info("Using strategy: " + strategy);
                logger.info("Thread count: " + std::to_string(config.powThreadCount));
                logger.info("Batch size: " + std::to_string(config.powBatchSize));
                logger.info("Suffix length: " + std::to_string(config.powSuffixLength));
                
                auto startTime = std::chrono::high_resolution_clock::now();
                
                // Solve the POW challenge
                POWSolver::Result result = POWSolver::solve(challengeStr, difficulty, strategy);
                
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
                
                if (!result.found) {
                    logger.error("Failed to find POW solution");
                    return false;
                }
                
                logger.success("Found POW solution in " + std::to_string(duration) + " seconds");
                logger.success("Solution: " + result.solution);
                logger.success("Hash: " + result.hash);
                
                // Send the solution
                logger.command(">>>", result.solution, "");
                if (!m_connection.writeLine(result.solution)) {
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
        
        // Log summary statistics
        auto protocol_end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(protocol_end_time - protocol_start_time).count();
        
        logger.header("Protocol Summary");
        logger.success("Protocol completed successfully in " + std::to_string(duration) + " seconds");
        logger.info("Total commands processed: " + std::to_string(command_count));
        
        logger.info("Command breakdown:");
        for (const auto& cmd : command_stats) {
            logger.info("  " + cmd.first + ": " + std::to_string(cmd.second));
        }
        
        return true;
    }
    
    bool isConnected() const {
        return m_connected && m_connection.isConnected();
    }
    
    int getPort() const {
        return m_port;
    }
    
    int getLastSuccessfulPort() const {
        return m_lastSuccessfulPort;
    }
    
    const UserInfo& getUserInfo() const {
        return m_userInfo;
    }
    
    void setUserInfo(const UserInfo& userInfo) {
        m_userInfo = userInfo;
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
    int m_lastSuccessfulPort;
};

// Main function implementation
int main(int argc, char* argv[]) {
    // Initialize network subsystem
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }
#endif
    
    // Process command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            config.printHelp(argv[0]);
#ifdef _WIN32
            WSACleanup();
#endif
            return 0;
        }
    }
    
    // Update configuration from command-line arguments
    config.updateFromArgs(argc, argv);
    
    // Print configuration
    config.printConfig();
    
    // Analyze POW settings for optimal performance
    if (config.analyzePow) {
        Utils::analyzePermutationSpace(config.powTestDifficulty, config.powSuffixLength);
    }
    
    try {
        // Get user input mode (interactive or use defaults)
        bool useInteractiveMode = true;
        if (config.useDefaultUserInfo) {
            useInteractiveMode = false;
        } else {
            std::string response;
            std::cout << "Use interactive mode to enter user information? (y/n): ";
            std::getline(std::cin, response);
            if (response == "n" || response == "N") {
                useInteractiveMode = false;
            }
        }
        
        // Set up user information
        UserInfo userInfo;
        
        if (useInteractiveMode) {
            // Collect user information interactively
            userInfo = UserInfo::collectFromUser();
        } else {
            // Use default information (replace with your actual information)
            userInfo.name = "Karthikeyan M";
            userInfo.emails = {"be_karthi@yahoo.co.in", "karkack@gmail.com"};
            userInfo.skype = "N/A";
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
        
        // Get certificate and key from the environment or command line
        std::string cert = config.certData;
        std::string key = config.keyData;
        
        // If not provided in config, use defaults from the assignment
        if (cert.empty() || key.empty()) {
            // Default certificates from the assignment
            cert = 
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
            
            key = 
                "-----BEGIN EC PRIVATE KEY-----\n"
                "MHcCAQEEIO1eB3IU8m/qEpWdMShCR++gZGHTjmz7MWfnEgyrvessoAoGCCqGSM49\n"
                "AwEHoUQDQgAE0WNjxYaOBrXjoBS4yulCFkjI8093T9vRq1ve5tzuYqAcqsO1qSbL\n"
                "Q3TXlSFGUDmT91WTdFt6RZk50IxRqM5YhA==\n"
                "-----END EC PRIVATE KEY-----\n";
        }
        
        // Ask if user wants to load certificates from files instead
        if (config.promptForCertFiles) {
            std::string response;
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
        }
        
        // Create the client
        ExatestClient client(config.serverHostname, cert, key, userInfo);
        
        logger.header("Connecting to " + config.serverHostname);
        
        // Connect with retry capability
        if (!client.connect(config.maxRetries, config.retryDelaySeconds)) {
            logger.error("Failed to establish connection to " + config.serverHostname);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        
        logger.header("Executing Protocol Sequence");
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (!client.runProtocol()) {
            logger.error("Protocol execution failed");
            client.disconnect();
#ifdef _WIN32
            WSACleanup();
#endif
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
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    } catch (...) {
        logger.error("Unknown exception occurred");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    
#ifdef _WIN32
    // Clean up Winsock
    WSACleanup();
#endif
    
    return 0;
}