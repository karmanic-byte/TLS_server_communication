#ifndef EXATEST_CLIENT_H
#define EXATEST_CLIENT_H

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <chrono>
#include <algorithm>
#include "utils.h"
#include "logger.h"
#include "config.h"
#include "pow_solver.h"
#include "tls_connection.h"

// Enhanced Client class for the Exatest protocol with improved user input handling
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

#endif // EXATEST_CLIENT_H