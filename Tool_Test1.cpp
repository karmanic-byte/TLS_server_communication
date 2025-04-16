/**
 * TLS Diagnostic Tool 1: POW Behavior Test
 * 
 * Tests the basic protocol flow with focus on POW challenge
 * - Reports detailed information about the challenge and solution
 * - Executes the full protocol flow
 * - Analyzes server responses
 * 
 * Compilation:
 * g++ -Wall -Wextra -g3 -O3 -std=c++17 tool1_pow_behavior.cpp -o tool1_pow_behavior.exe -lssl -lcrypto -lws2_32 -pthread
 */

 #define TLS_DIAGNOSTIC_COMMON_IMPL
 #include "Diagnostic_Common.h"
 
 class POWBehaviorTest {
 public:
     POWBehaviorTest(const DiagnosticConfig& config) 
         : m_config(config), m_connected(false), m_port(config.port > 0 ? config.port : VALID_PORTS[1]) {
         
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
     
     ~POWBehaviorTest() {
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
     
     // Test POW behavior
     bool runTest() {
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
     
     bool isConnected() const {
         return m_connected && m_connection.isConnected();
     }
     
     int getPort() const {
         return m_port;
     }
 
 private:
     DiagnosticConfig m_config;
     std::string m_certFile;
     std::string m_keyFile;
     TLSConnection m_connection;
     bool m_connected;
     int m_port;
 };
 
 int main(int argc, char* argv[]) {
     // Initialize Winsock
     if (!initializeWinsock()) {
         return 1;
     }
     
     // Parse command line arguments
     auto config = parseCommandLine(argc, argv);
     
     Utils::printBanner("TLS Diagnostic Tool 1: POW Behavior Test");
     
     std::cout << "Target host: " << Color::BOLD << config.hostname << Color::RESET << std::endl;
     if (config.port > 0) {
         std::cout << "Port: " << Color::BOLD << config.port << Color::RESET << std::endl;
     } else {
         std::cout << "Ports: " << Color::BOLD << "Auto (try all)" << Color::RESET << std::endl;
     }
     std::cout << "AuthData variant: " << Color::BOLD << config.authDataVariant << Color::RESET << std::endl;
     std::cout << "POW threads: " << Color::BOLD << POW_THREAD_COUNT << Color::RESET << std::endl;
     std::cout << std::endl;
     
     try {
         POWBehaviorTest test(config);
         
         logger.header("Connecting to " + config.hostname);
         
         if (!test.connect()) {
             logger.error("Failed to establish connection to " + config.hostname);
             cleanupWinsock();
             return 1;
         }
         
         bool result = test.runTest();
         
         test.disconnect();
         
         if (result) {
             logger.header("Test Completed Successfully");
         } else {
             logger.header("Test Failed");
         }
         
     } catch (const std::exception& e) {
         logger.error("Exception: " + std::string(e.what()));
         cleanupWinsock();
         return 1;
     } catch (...) {
         logger.error("Unknown exception occurred");
         cleanupWinsock();
         return 1;
     }
     
     // Clean up Winsock
     cleanupWinsock();
     
     return 0;
 }