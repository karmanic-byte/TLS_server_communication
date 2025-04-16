#ifndef POW_SOLVER_H
#define POW_SOLVER_H

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <random>
#include "utils.h"
#include "logger.h"
#include "config.h"

// Thread pool for parallel POW computation with enhanced performance monitoring
class POWThreadPool {
public:
    POWThreadPool(int numThreads, const std::string& challenge, int difficulty) 
        : m_challenge(challenge), m_difficulty(difficulty), m_targetPrefix(difficulty, '0'),
          m_running(true), m_found(false), m_totalAttempts(0), m_bestZeroCount(0) {
        
        logger.info("Initializing POW solver with " + std::to_string(numThreads) + " threads");
        logger.info("Challenge: " + challenge);
        logger.info("Difficulty: " + std::to_string(difficulty) + " (target: " + m_targetPrefix + "...)");
        
        m_startTime = std::chrono::high_resolution_clock::now();
        
        // Start the worker threads
        for (int i = 0; i < numThreads; ++i) {
            m_threads.emplace_back(&POWThreadPool::workerThread, this, i);
        }
        
        // Start the statistics thread if enabled
        if (config.detailedPowStats) {
            m_statsThread = std::thread(&POWThreadPool::statsThread, this);
        }
    }
    
    ~POWThreadPool() {
        // Signal all threads to stop
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_running = false;
        }
        m_condition.notify_all();
        
        // Wait for all threads to finish
        for (auto& thread : m_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        // Stop the statistics thread if it's running
        if (config.detailedPowStats && m_statsThread.joinable()) {
            m_statsThread.join();
        }
        
        // Print final statistics
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - m_startTime).count();
        
        uint64_t hashRate = (duration > 0) ? (m_totalAttempts.load() / duration) : 0;
        
        logger.info("POW solve completed with " + std::to_string(m_totalAttempts.load()) + " attempts");
        logger.info("Average hash rate: " + std::to_string(hashRate) + " hashes/second");
        logger.info("Total duration: " + std::to_string(duration) + " seconds");
    }
    
    // Wait for a solution
    std::string waitForSolution() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_condition.wait(lock, [this] { return m_found || !m_running; });
        
        if (m_found) {
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - m_startTime).count();
            
            logger.success("POW solution found in " + std::to_string(duration) + " seconds");
            logger.success("Solution: " + m_solution);
            logger.success("Hash: " + Utils::sha1(m_challenge + m_solution));
            
            return m_solution;
        }
        
        return "";
    }

private:
    // Thread that periodically reports POW solving statistics
    void statsThread() {
        logger.debug("POW statistics thread started");
        
        while (true) {
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                if (!m_running || m_found) {
                    break;
                }
            }
            
            // Sleep for the statistics interval
            std::this_thread::sleep_for(std::chrono::seconds(config.powStatsInterval));
            
            // Calculate statistics
            auto now = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime).count();
            
            uint64_t attempts = m_totalAttempts.load();
            uint64_t rate = (duration > 0) ? (attempts / duration) : 0;
            
            std::string bestHashInfo;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                bestHashInfo = m_bestHash.substr(0, std::min(size_t(16), m_bestHash.length())) + 
                              " (" + std::to_string(m_bestZeroCount) + " zeros)";
            }
            
            // Log statistics
            logger.powStats(attempts, rate, bestHashInfo, duration);
        }
        
        logger.debug("POW statistics thread exiting");
    }
    
    void workerThread(int id) {
        logger.debug("POW Worker thread " + std::to_string(id) + " started");
        
        // Initialize thread-local random number generator with a unique seed
        std::random_device rd;
        std::mt19937 gen(rd() + id * 1000); // Add thread ID to seed for better distribution
        
        const int suffixLength = config.powSuffixLength;
        uint64_t localAttempts = 0;
        int localBestZeros = 0;
        std::string localBestHash;
        std::string localBestSuffix;
        
        while (true) {
            // Check if we should stop
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!m_running || m_found) {
                    break;
                }
            }
            
            // Process a batch of random strings
            for (int i = 0; i < config.powBatchSize; ++i) {
                // Generate random suffix
                std::string suffix = Utils::randomPowString(suffixLength, gen);
                
                // Compute SHA-1 hash using the optimized EVP interface
                std::string hash = Utils::sha1_evp(m_challenge + suffix);
                
                // Increment attempt counter
                localAttempts++;
                
                // Check if hash meets the difficulty requirement
                if (hash.compare(0, m_difficulty, m_targetPrefix) == 0) {
                    // Found a solution!
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (!m_found) {
                        m_found = true;
                        m_solution = suffix;
                        logger.success("POW Worker " + std::to_string(id) + " found solution: " + suffix);
                        logger.debug("Hash: " + hash);
                    }
                    m_condition.notify_all();
                    m_totalAttempts += localAttempts;
                    return;
                }
                
                // Track the best hash we've seen so far (for reporting)
                int zeroCount = 0;
                while (zeroCount < static_cast<int>(hash.length()) && hash[zeroCount] == '0') {
                    zeroCount++;
                }
                
                if (zeroCount > localBestZeros) {
                    localBestZeros = zeroCount;
                    localBestHash = hash;
                    localBestSuffix = suffix;
                    
                    // If this is better than the best we've seen globally, update that too
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (zeroCount > m_bestZeroCount) {
                        m_bestZeroCount = zeroCount;
                        m_bestHash = hash;
                        m_bestSuffix = suffix;
                        
                        // Log significant improvements
                        if (zeroCount >= m_difficulty) {
                            logger.debug("Thread " + std::to_string(id) + " found hash with " + 
                                        std::to_string(zeroCount) + " leading zeros: " + hash);
                        }
                    }
                }
            }
            
            // Update total attempts counter periodically
            m_totalAttempts += localAttempts;
            localAttempts = 0;
            
            // Periodically check if another thread found a solution
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_found || !m_running) {
                    break;
                }
            }
        }
        
        // Add remaining attempts to the total
        if (localAttempts > 0) {
            m_totalAttempts += localAttempts;
        }
        
        logger.debug("POW Worker thread " + std::to_string(id) + " exiting");
    }
    
    std::string m_challenge;
    int m_difficulty;
    std::string m_targetPrefix;
    std::vector<std::thread> m_threads;
    std::thread m_statsThread;
    std::mutex m_mutex;
    std::condition_variable m_condition;
    std::atomic<bool> m_running;
    bool m_found;
    std::string m_solution;
    std::atomic<uint64_t> m_totalAttempts;
    int m_bestZeroCount;
    std::string m_bestHash;
    std::string m_bestSuffix;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_startTime;
};

#endif // POW_SOLVER_H