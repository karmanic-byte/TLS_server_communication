#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <set>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>
#include <vector>
#include <algorithm>
#include <utility>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <queue>              
#include <mutex>              
#include <condition_variable>
#include <functional>
#include <deque>       // Added for std::deque
#include <map>         // Added for std::map 
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

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

// Set of valid country names
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
    // Convert byte array to hex string - optimized version
    inline std::string bytesToHex(const unsigned char* data, size_t len) {
        static const char hex_digits[] = "0123456789abcdef";
        std::string result(len * 2, 0);
        
        for (size_t i = 0; i < len; i++) {
            result[i * 2] = hex_digits[(data[i] >> 4) & 0x0F];
            result[i * 2 + 1] = hex_digits[data[i] & 0x0F];
        }
        
        return result;
    }

    // Compute SHA-1 hash
    inline std::string sha1(const std::string& input) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
        return bytesToHex(hash, SHA_DIGEST_LENGTH);
    }

    // Compute SHA-1 hash with OpenSSL EVP interface for better performance
    inline std::string sha1_evp(const std::string& input) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        EVP_MD_CTX* context = EVP_MD_CTX_new();
        
        EVP_DigestInit_ex(context, EVP_sha1(), NULL);
        EVP_DigestUpdate(context, input.c_str(), input.length());
        EVP_DigestFinal_ex(context, hash, NULL);
        
        EVP_MD_CTX_free(context);
        
        return bytesToHex(hash, SHA_DIGEST_LENGTH);
    }
    
    // Count leading zeros in a hexadecimal string
    inline int countLeadingZeros(const std::string& hash) {
        int count = 0;
        while (count < static_cast<int>(hash.length()) && hash[count] == '0') {
            count++;
        }
        return count;
    }

    // Get an optimized character set for POW (excluding disallowed characters)
    inline const std::string& getOptimizedCharSet() {
        static const std::string charSet =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // All printable ASCII except space, tab, newline
        return charSet;
    }
    
    // Get an alternative character set with different distribution
    inline const std::string& getAlternativeCharSet() {
        static const std::string charSet =
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // Different order for different hash distribution
        return charSet;
    }
    
    // Get a biased character set that may produce more leading zeros
    inline const std::string& getBiasedCharSet() {
        // Based on empirical analysis of SHA-1, some characters might
        // produce more leading zeros. This is a theoretical approach.
        static const std::string charSet =
            "0123456789"
            "abcdefABCDEF"  // Hex digits first (might influence hash)
            "ghijklmnopqrstuvwxyz"
            "GHIJKLMNOPQRSTUVWXYZ"
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        return charSet;
    }

    // Generate random string for POW - avoiding \n\r\t and space as required
    // Optimized version with pre-allocated buffer and direct character set
    inline std::string randomPowString(size_t length, std::mt19937& gen) {
        const std::string& charSet = getOptimizedCharSet();
        std::uniform_int_distribution<> dist(0, charSet.size() - 1);
        
        std::string result(length, 0);
        for (size_t i = 0; i < length; ++i) {
            result[i] = charSet[dist(gen)];
        }
        
        return result;
    }
    
    // Get random bytes from the OS
    inline std::vector<unsigned char> getRandomBytes(size_t count) {
        std::vector<unsigned char> bytes(count);
        
#ifdef _WIN32
        // Windows implementation using cryptographic provider
        HCRYPTPROV hCryptProv;
        if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hCryptProv, count, bytes.data());
            CryptReleaseContext(hCryptProv, 0);
        } else {
            // Fallback to std::random_device
            std::random_device rd;
            for (size_t i = 0; i < count; i++) {
                bytes[i] = static_cast<unsigned char>(rd() & 0xFF);
            }
        }
#else
        // Linux/UNIX implementation
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd != -1) {
            read(fd, bytes.data(), count);
            close(fd);
        } else {
            // Fallback to std::random_device
            std::random_device rd;
            for (size_t i = 0; i < count; i++) {
                bytes[i] = static_cast<unsigned char>(rd() & 0xFF);
            }
        }
#endif
        
        return bytes;
    }
    
    // Generate random string using high-quality OS entropy
    inline std::string secureRandomString(size_t length) {
        const std::string& charSet = getOptimizedCharSet();
        std::vector<unsigned char> randomBytes = getRandomBytes(length);
        
        std::string result(length, 0);
        for (size_t i = 0; i < length; ++i) {
            result[i] = charSet[randomBytes[i] % charSet.size()];
        }
        
        return result;
    }

    // Check if string is valid UTF-8
    inline bool isValidUTF8(const std::string& str) {
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
    inline std::string ensureUTF8(const std::string& input) {
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
    inline std::pair<std::string, std::string> parseCommand(const std::string& line) {
        size_t spacePos = line.find(' ');
        if (spacePos == std::string::npos) {
            return std::make_pair(line, "");
        }
        
        std::string command = line.substr(0, spacePos);
        std::string args = line.substr(spacePos + 1);
        
        return std::make_pair(command, args);
    }

    // Save cert and key to temporary files
    inline std::pair<std::string, std::string> saveCertAndKey(const std::string& cert, const std::string& key) {
#ifdef _WIN32
        std::string certFile = "temp_cert_" + std::to_string(GetCurrentProcessId()) + ".pem";
        std::string keyFile = "temp_key_" + std::to_string(GetCurrentProcessId()) + ".pem";
#else
        std::string certFile = "temp_cert_" + std::to_string(getpid()) + ".pem";
        std::string keyFile = "temp_key_" + std::to_string(getpid()) + ".pem";
#endif
        
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
        
        // Set appropriate permissions for key file on UNIX systems
#ifndef _WIN32
        chmod(keyFile.c_str(), 0600);  // Read/write for owner only
#endif
        
        return std::make_pair(certFile, keyFile);
    }

    // Clean up temporary files
    inline void cleanupTempFiles(const std::string& certFile, const std::string& keyFile) {
        remove(certFile.c_str());
        remove(keyFile.c_str());
    }
    
    // Generate permutation space statistics for POW optimization
    inline void analyzePermutationSpace(int difficulty, int suffixLength) {
        // Calculate the target probability
        double targetProbability = std::pow(16.0, -difficulty);
        
        // Calculate the search space size
        const std::string& charSet = getOptimizedCharSet();
        double searchSpace = std::pow(charSet.size(), suffixLength);
        
        // Calculate expected number of attempts
        double expectedAttempts = 1.0 / targetProbability;
        
        // Calculate probability of finding solution with N attempts
        auto calculateSuccessProbability = [targetProbability](uint64_t attempts) {
            return 1.0 - std::pow(1.0 - targetProbability, attempts);
        };
        
        std::cout << "POW Analysis:" << std::endl;
        std::cout << "  Difficulty: " << difficulty << " (target: " << std::string(difficulty, '0') << "...)" << std::endl;
        std::cout << "  Suffix length: " << suffixLength << std::endl;
        std::cout << "  Character set size: " << charSet.size() << std::endl;
        std::cout << "  Target probability: 1 in " << static_cast<uint64_t>(expectedAttempts) << std::endl;
        std::cout << "  Search space size: " << searchSpace << std::endl;
        std::cout << "  Expected attempts: " << expectedAttempts << std::endl;
        std::cout << "  Success probability after:" << std::endl;
        std::cout << "    10% of expected attempts: " << (calculateSuccessProbability(expectedAttempts * 0.1) * 100.0) << "%" << std::endl;
        std::cout << "    50% of expected attempts: " << (calculateSuccessProbability(expectedAttempts * 0.5) * 100.0) << "%" << std::endl;
        std::cout << "    100% of expected attempts: " << (calculateSuccessProbability(expectedAttempts) * 100.0) << "%" << std::endl;
        std::cout << "    200% of expected attempts: " << (calculateSuccessProbability(expectedAttempts * 2.0) * 100.0) << "%" << std::endl;
    }
    
    // Check if GPU acceleration is available
#ifdef USE_OPENCL
    inline bool isGPUAvailable() {
        try {
            cl_uint platformCount;
            cl_int error = clGetPlatformIDs(0, nullptr, &platformCount);
            if (error != CL_SUCCESS || platformCount == 0) {
                return false;
            }
            
            std::vector<cl_platform_id> platforms(platformCount);
            error = clGetPlatformIDs(platformCount, platforms.data(), nullptr);
            if (error != CL_SUCCESS) {
                return false;
            }
            
            for (cl_uint i = 0; i < platformCount; i++) {
                cl_uint deviceCount;
                error = clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, 0, nullptr, &deviceCount);
                if (error == CL_SUCCESS && deviceCount > 0) {
                    return true;
                }
            }
            
            return false;
        } catch (...) {
            return false;
        }
    }
#else
    inline bool isGPUAvailable() {
        return false;
    }
#endif
    
    // Simple thread pool for general parallel tasks
    class ThreadPool {
    public:
    std::vector<std::thread> m_workers;

        ThreadPool(size_t numThreads) : m_stop(false) {
            for (size_t i = 0; i < numThreads; ++i) {
                m_workers.emplace_back([this] {
                    while (true) {
                        std::function<void()> task;
                        {
                            std::unique_lock<std::mutex> lock(m_mutex);
                            m_condition.wait(lock, [this] { 
                                return m_stop || !m_tasks.empty(); 
                            });
                            
                            if (m_stop && m_tasks.empty()) {
                                return;
                            }
                            
                            task = std::move(m_tasks.front());
                            m_tasks.pop_front();
                        }
                        
                        task();
                    }
                });
            }
        }
        
        template<class F>
        void enqueue(F&& f) {
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                if (m_stop) {
                    throw std::runtime_error("ThreadPool has been stopped");
                }
                m_tasks.emplace_back(std::forward<F>(f));
            }
            m_condition.notify_one();
        }
        
        ~ThreadPool() {
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_stop = true;
            }
            m_condition.notify_all();
            for (auto& worker : m_workers) {
                worker.join();
            }
        }
        
    private:
        //std::vector<std::thread> m_workers;
        std::deque<std::function<void()>> m_tasks;
        std::mutex m_mutex;
        std::condition_variable m_condition;
        bool m_stop;
    };
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

#endif // UTILS_H