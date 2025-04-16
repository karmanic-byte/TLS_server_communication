#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <set>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <queue>              // For std::queue
#include <mutex>              // For std::mutex and std::unique_lock
#include <condition_variable> // For std::condition_variable
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
    // Convert byte array to hex string
    inline std::string bytesToHex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; i++) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
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

    // Generate random string for POW - avoiding \n\r\t and space as required
    inline std::string randomPowString(size_t length, std::mt19937& gen) {
        static const char allowed_chars[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // All printable ASCII except space, tab, newline
        
        const int char_count = sizeof(allowed_chars) - 1;
        std::uniform_int_distribution<> dist(0, char_count - 1);
        
        std::string result;
        result.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            result += allowed_chars[dist(gen)];
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
    inline void cleanupTempFiles(const std::string& certFile, const std::string& keyFile) {
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

#endif // UTILS_H