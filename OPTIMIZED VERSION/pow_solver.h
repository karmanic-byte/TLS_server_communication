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
#include <algorithm>
#include <functional>
#include <memory>
#include "utils.h"
#include "logger.h"
#include "config.h"

#ifdef USE_OPENCL
#include <CL/cl.h>
#include "opencl_utils.h"
#endif

class POWSolver {
public:
    struct Result {
        std::string solution;
        std::string hash;
        bool found;
    };

    // Base class for different solver strategies
    class SolverStrategy {
    public:
        virtual ~SolverStrategy() = default;
        virtual Result solve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) = 0;
        virtual std::string getName() const = 0;
    };

    // CPU-based multi-threaded solver
    class CPUThreadPoolStrategy : public SolverStrategy {
    public:
        CPUThreadPoolStrategy(int numThreads, int batchSize, int suffixLength, bool detailedStats, int statsInterval)
            : m_numThreads(numThreads), 
              m_batchSize(batchSize), 
              m_suffixLength(suffixLength),
              m_detailedStats(detailedStats),
              m_statsInterval(statsInterval),
              m_totalAttempts(0), 
              m_bestZeroCount(0) {}

        Result solve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) override {
            Result result;
            result.found = false;
            
            m_challenge = challenge;
            m_difficulty = difficulty;
            m_targetPrefix = std::string(difficulty, '0');
            m_running = true;
            m_found = false;
            m_solution.clear();
            m_bestHash.clear();
            m_bestSuffix.clear();
            m_totalAttempts = 0;
            m_bestZeroCount = 0;
            
            logger.info("Starting CPU thread pool solver with " + std::to_string(m_numThreads) + " threads");
            logger.info("Challenge: " + challenge);
            logger.info("Difficulty: " + std::to_string(difficulty) + " (target: " + m_targetPrefix + "...)");
            
            m_startTime = std::chrono::high_resolution_clock::now();
            
            // Start the worker threads
            std::vector<std::thread> threads;
            for (int i = 0; i < m_numThreads; ++i) {
                threads.emplace_back(&CPUThreadPoolStrategy::workerThread, this, i, std::ref(should_stop));
            }
            
            // Start the statistics thread if enabled
            std::thread statsThread;
            if (m_detailedStats) {
                statsThread = std::thread(&CPUThreadPoolStrategy::statsThread, this, std::ref(should_stop));
            }
            
            // Wait for a solution or stop signal
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_condition.wait(lock, [this, &should_stop] { 
                    return m_found || should_stop.load() || !m_running; 
                });
            }
            
            // Signal all threads to stop
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_running = false;
            }
            m_condition.notify_all();
            
            // Wait for all threads to finish
            for (auto& thread : threads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            
            // Stop the statistics thread if it's running
            if (m_detailedStats && statsThread.joinable()) {
                statsThread.join();
            }
            
            // Print final statistics
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - m_startTime).count();
            
            uint64_t hashRate = (duration > 0) ? (m_totalAttempts.load() / duration) : 0;
            
            logger.info("POW solve completed with " + std::to_string(m_totalAttempts.load()) + " attempts");
            logger.info("Average hash rate: " + std::to_string(hashRate) + " hashes/second");
            logger.info("Total duration: " + std::to_string(duration) + " seconds");
            
            if (m_found) {
                result.found = true;
                result.solution = m_solution;
                result.hash = Utils::sha1(m_challenge + m_solution);
                
                logger.success("Solution found: " + result.solution);
                logger.success("Hash: " + result.hash);
            }
            
            return result;
        }

        std::string getName() const override {
            return "CPU Thread Pool";
        }

    private:
        void statsThread(std::atomic<bool>& should_stop) {
            logger.debug("POW statistics thread started");
            
            while (true) {
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    if (!m_running || m_found || should_stop.load()) {
                        break;
                    }
                }
                
                // Sleep for the statistics interval
                std::this_thread::sleep_for(std::chrono::seconds(m_statsInterval));
                
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
        
        void workerThread(int id, std::atomic<bool>& should_stop) {
            logger.debug("POW Worker thread " + std::to_string(id) + " started");
            
            // Initialize thread-local random number generator with a unique seed
            std::random_device rd;
            std::mt19937 gen(rd() + id * 1000); // Add thread ID to seed for better distribution
            
            const int suffixLength = m_suffixLength;
            uint64_t localAttempts = 0;
            int localBestZeros = 0;
            std::string localBestHash;
            std::string localBestSuffix;
            
            // Create optimized character set for maximum randomness but also higher probability
            // of finding a solution with the given constraint
            const std::string charSet = Utils::getOptimizedCharSet();
            std::uniform_int_distribution<> dist(0, charSet.size() - 1);
            
            // For improved efficiency, pre-allocate the suffix buffer
            std::string suffix(suffixLength, '0');
            
            while (true) {
                // Check if we should stop
                if (should_stop.load()) {
                    break;
                }
                
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (!m_running || m_found) {
                        break;
                    }
                }
                
                // Process a batch of random strings
                for (int i = 0; i < m_batchSize; ++i) {
                    // Generate random suffix (reuse buffer for less allocations)
                    for (int j = 0; j < suffixLength; ++j) {
                        suffix[j] = charSet[dist(gen)];
                    }
                    
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
                    int zeroCount = Utils::countLeadingZeros(hash);
                    
                    if (zeroCount > localBestZeros) {
                        localBestZeros = zeroCount;
                        localBestHash = hash;
                        localBestSuffix = suffix;
                        
                        // If this is better than the best we've seen globally, update that too
                        if (m_detailedStats) {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            if (zeroCount > m_bestZeroCount) {
                                m_bestZeroCount = zeroCount;
                                m_bestHash = hash;
                                m_bestSuffix = suffix;
                                
                                // Log significant improvements
                                if (zeroCount >= m_difficulty - 1) {
                                    logger.debug("Thread " + std::to_string(id) + " found hash with " + 
                                                std::to_string(zeroCount) + " leading zeros: " + hash.substr(0, 16) + "...");
                                }
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
                    if (m_found || !m_running || should_stop.load()) {
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
        
        int m_numThreads;
        int m_batchSize;
        int m_suffixLength;
        bool m_detailedStats;
        int m_statsInterval;
        std::string m_challenge;
        int m_difficulty;
        std::string m_targetPrefix;
        std::mutex m_mutex;
        std::condition_variable m_condition;
        bool m_running;
        bool m_found;
        std::string m_solution;
        std::atomic<uint64_t> m_totalAttempts;
        int m_bestZeroCount;
        std::string m_bestHash;
        std::string m_bestSuffix;
        std::chrono::time_point<std::chrono::high_resolution_clock> m_startTime;
    };

#ifdef USE_OPENCL
    // OpenCL GPU-based solver
    class GPUOpenCLStrategy : public SolverStrategy {
    public:
        GPUOpenCLStrategy(int platformId = 0, int deviceId = 0, 
                         int localWorkSize = 64, int globalWorkSizeFactor = 8192,
                         bool detailedStats = true, int statsInterval = 1)
            : m_platformId(platformId), 
              m_deviceId(deviceId),
              m_localWorkSize(localWorkSize),
              m_globalWorkSizeFactor(globalWorkSizeFactor),
              m_detailedStats(detailedStats),
              m_statsInterval(statsInterval),
              m_totalAttempts(0) {}

        Result solve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) override {
            Result result;
            result.found = false;
            
            logger.info("Starting GPU OpenCL solver");
            logger.info("Challenge: " + challenge);
            logger.info("Difficulty: " + std::to_string(difficulty));
            
            try {
                // Initialize OpenCL
                OpenCLUtils::Context context(m_platformId, m_deviceId);
                logger.info("Using device: " + context.getDeviceName());
                
                // Build the program
                std::string kernelSource = OpenCLUtils::getHashKernelSource();
                cl_program program = OpenCLUtils::buildProgram(context.getContext(), context.getDevice(), kernelSource);
                
                // Create kernel
                cl_int err;
                cl_kernel kernel = clCreateKernel(program, "sha1_search", &err);
                if (err != CL_SUCCESS) {
                    logger.error("Failed to create OpenCL kernel: " + std::to_string(err));
                    return result;
                }
                
                // Set up memory objects
                const size_t challengeLen = challenge.length();
                const char* challengeData = challenge.c_str();
                
                cl_mem challengeBuffer = clCreateBuffer(context.getContext(), CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                                       challengeLen, (void*)challengeData, &err);
                if (err != CL_SUCCESS) {
                    logger.error("Failed to create challenge buffer: " + std::to_string(err));
                    return result;
                }
                
                // Output buffer for the solution
                char solutionOutput[256] = {0};
                cl_mem outputBuffer = clCreateBuffer(context.getContext(), CL_MEM_WRITE_ONLY,
                                                   sizeof(solutionOutput), NULL, &err);
                if (err != CL_SUCCESS) {
                    logger.error("Failed to create output buffer: " + std::to_string(err));
                    return result;
                }
                
                // Found flag
                cl_int foundFlag = 0;
                cl_mem foundBuffer = clCreateBuffer(context.getContext(), CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                                                  sizeof(cl_int), &foundFlag, &err);
                
                // Set kernel arguments
                err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &challengeBuffer);
                err |= clSetKernelArg(kernel, 1, sizeof(cl_int), &challengeLen);
                err |= clSetKernelArg(kernel, 2, sizeof(cl_int), &difficulty);
                err |= clSetKernelArg(kernel, 3, sizeof(cl_mem), &outputBuffer);
                err |= clSetKernelArg(kernel, 4, sizeof(cl_mem), &foundBuffer);
                if (err != CL_SUCCESS) {
                    logger.error("Failed to set kernel arguments: " + std::to_string(err));
                    return result;
                }
                
                // Local and global work sizes
                size_t localWorkSize = m_localWorkSize;
                size_t globalWorkSize = localWorkSize * m_globalWorkSizeFactor;
                
                // Start timing
                auto startTime = std::chrono::high_resolution_clock::now();
                
                // Stats thread
                std::atomic<uint64_t> iterationCount(0);
                std::thread statsThread;
                if (m_detailedStats) {
                    statsThread = std::thread([&]() {
                        while (!should_stop.load() && !foundFlag) {
                            std::this_thread::sleep_for(std::chrono::seconds(m_statsInterval));
                            
                            auto now = std::chrono::high_resolution_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
                            if (duration == 0) continue;
                            
                            uint64_t attempts = iterationCount.load() * globalWorkSize;
                            uint64_t rate = attempts / duration;
                            
                            logger.powStats(attempts, rate, "N/A (GPU)", duration);
                        }
                    });
                }
                
                // Main processing loop
                uint64_t iteration = 0;
                while (!should_stop.load() && !foundFlag) {
                    // Update seed for this round
                    cl_ulong seed = (iteration << 32) | (iteration & 0xFFFFFFFF);
                    err = clSetKernelArg(kernel, 5, sizeof(cl_ulong), &seed);
                    if (err != CL_SUCCESS) {
                        logger.error("Failed to update seed: " + std::to_string(err));
                        break;
                    }
                    
                    // Enqueue kernel
                    err = clEnqueueNDRangeKernel(context.getCommandQueue(), kernel, 1, NULL,
                                               &globalWorkSize, &localWorkSize, 0, NULL, NULL);
                    if (err != CL_SUCCESS) {
                        logger.error("Failed to enqueue kernel: " + std::to_string(err));
                        break;
                    }
                    
                    // Check if a solution was found
                    err = clEnqueueReadBuffer(context.getCommandQueue(), foundBuffer, CL_TRUE, 0,
                                            sizeof(cl_int), &foundFlag, 0, NULL, NULL);
                    if (err != CL_SUCCESS) {
                        logger.error("Failed to read found flag: " + std::to_string(err));
                        break;
                    }
                    
                    iteration++;
                    iterationCount.store(iteration);
                    
                    if (foundFlag) {
                        // Read the solution
                        err = clEnqueueReadBuffer(context.getCommandQueue(), outputBuffer, CL_TRUE, 0,
                                                sizeof(solutionOutput), solutionOutput, 0, NULL, NULL);
                        if (err != CL_SUCCESS) {
                            logger.error("Failed to read solution: " + std::to_string(err));
                            break;
                        }
                        
                        result.found = true;
                        result.solution = std::string(solutionOutput);
                        result.hash = Utils::sha1(challenge + result.solution);
                        break;
                    }
                }
                
                // Clean up stats thread
                if (m_detailedStats && statsThread.joinable()) {
                    statsThread.join();
                }
                
                // Final stats
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
                uint64_t attempts = iteration * globalWorkSize;
                uint64_t rate = (duration > 0) ? (attempts / duration) : 0;
                
                m_totalAttempts = attempts;
                
                logger.info("GPU OpenCL solver completed with approximate " + std::to_string(attempts) + " attempts");
                logger.info("Average hash rate: " + std::to_string(rate) + " hashes/second");
                logger.info("Total duration: " + std::to_string(duration) + " seconds");
                
                if (result.found) {
                    logger.success("Solution found: " + result.solution);
                    logger.success("Hash: " + result.hash);
                }
                
                // Cleanup OpenCL resources
                clReleaseMemObject(challengeBuffer);
                clReleaseMemObject(outputBuffer);
                clReleaseMemObject(foundBuffer);
                clReleaseKernel(kernel);
                clReleaseProgram(program);
                
            } catch (const std::exception& e) {
                logger.error("OpenCL error: " + std::string(e.what()));
            }
            
            return result;
        }

        std::string getName() const override {
            return "GPU OpenCL";
        }

    private:
        int m_platformId;
        int m_deviceId;
        int m_localWorkSize;
        int m_globalWorkSizeFactor;
        bool m_detailedStats;
        int m_statsInterval;
        std::atomic<uint64_t> m_totalAttempts;
    };
#endif

    // Hybrid solver that tries multiple strategies
    class HybridStrategy : public SolverStrategy {
    public:
        HybridStrategy(const std::vector<std::shared_ptr<SolverStrategy>>& strategies)
            : m_strategies(strategies) {}
        
        Result solve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) override {
            Result result;
            result.found = false;
            
            logger.info("Starting hybrid solver with " + std::to_string(m_strategies.size()) + " strategies");
            
            std::vector<std::thread> threads;
            std::vector<Result> results(m_strategies.size());
            std::vector<std::atomic<bool>> strategyComplete(m_strategies.size());
            
            for (size_t i = 0; i < m_strategies.size(); i++) {
                strategyComplete[i] = false;
                
                threads.emplace_back([this, i, &challenge, difficulty, &should_stop, &results, &strategyComplete]() {
                    logger.info("Starting strategy: " + m_strategies[i]->getName());
                    results[i] = m_strategies[i]->solve(challenge, difficulty, should_stop);
                    strategyComplete[i] = true;
                    
                    if (results[i].found) {
                        should_stop.store(true);
                    }
                });
            }
            
            // Wait for all strategies to complete or for one to find a solution
            for (auto& thread : threads) {
                thread.join();
            }
            
            // Use the first successful result
            for (size_t i = 0; i < results.size(); i++) {
                if (results[i].found) {
                    logger.success("Strategy " + m_strategies[i]->getName() + " found solution");
                    return results[i];
                }
            }
            
            logger.warning("No strategy found a solution");
            return result;
        }
        
        std::string getName() const override {
            return "Hybrid";
        }
        
    private:
        std::vector<std::shared_ptr<SolverStrategy>> m_strategies;
    };

    // Probabilistic strategy that adaptively tries different approaches
    class AdaptiveStrategy : public SolverStrategy {
    public:
        AdaptiveStrategy(int suffixLength, bool detailedStats = true)
            : m_suffixLength(suffixLength), m_detailedStats(detailedStats) {}
        
        Result solve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) override {
            Result result;
            result.found = false;
            
            logger.info("Starting adaptive POW solver");
            logger.info("Challenge: " + challenge);
            logger.info("Difficulty: " + std::to_string(difficulty));
            
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // For easier difficulties, use a simple approach
            if (difficulty <= 5) {
                result = simpleSolve(challenge, difficulty, should_stop);
            }
            // For medium difficulties, use a character distribution approach
            else if (difficulty <= 7) {
                result = distributionSolve(challenge, difficulty, should_stop);
            }
            // For hard difficulties, use an optimized approach
            else {
                result = optimizedSolve(challenge, difficulty, should_stop);
            }
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
            
            logger.info("Adaptive solver completed in " + std::to_string(duration) + " seconds");
            
            if (result.found) {
                logger.success("Solution found: " + result.solution);
                logger.success("Hash: " + result.hash);
            }
            
            return result;
        }
        
        std::string getName() const override {
            return "Adaptive";
        }
        
    private:
        Result simpleSolve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) {
            logger.info("Using simple solving approach for difficulty " + std::to_string(difficulty));
            
            std::random_device rd;
            std::mt19937 gen(rd());
            
            const std::string charSet = Utils::getOptimizedCharSet();
            std::uniform_int_distribution<> dist(0, charSet.size() - 1);
            
            Result result;
            result.found = false;
            
            std::string suffix(m_suffixLength, '0');
            uint64_t attempts = 0;
            
            while (!should_stop.load() && !result.found) {
                // Generate random suffix
                for (int j = 0; j < m_suffixLength; ++j) {
                    suffix[j] = charSet[dist(gen)];
                }
                
                // Compute hash
                std::string hash = Utils::sha1_evp(challenge + suffix);
                attempts++;
                
                // Check if it meets the target
                if (hash.compare(0, difficulty, std::string(difficulty, '0')) == 0) {
                    result.found = true;
                    result.solution = suffix;
                    result.hash = hash;
                }
                
                // Periodically log progress
                if (m_detailedStats && attempts % 10000 == 0) {
                    logger.debug("Simple solver: " + std::to_string(attempts) + " attempts");
                }
            }
            
            logger.info("Simple solver completed with " + std::to_string(attempts) + " attempts");
            return result;
        }
        
        Result distributionSolve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) {
            logger.info("Using character distribution approach for difficulty " + std::to_string(difficulty));
            
            // Use a biased character distribution that favors characters that tend to
            // produce more leading zeros in SHA-1 hashes
            const std::string biasedCharSet = Utils::getBiasedCharSet();
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dist(0, biasedCharSet.size() - 1);
            
            Result result;
            result.found = false;
            
            std::string suffix(m_suffixLength, '0');
            uint64_t attempts = 0;
            
            while (!should_stop.load() && !result.found) {
                // Generate random suffix with biased distribution
                for (int j = 0; j < m_suffixLength; ++j) {
                    suffix[j] = biasedCharSet[dist(gen)];
                }
                
                // Compute hash
                std::string hash = Utils::sha1_evp(challenge + suffix);
                attempts++;
                
                // Check if it meets the target
                if (hash.compare(0, difficulty, std::string(difficulty, '0')) == 0) {
                    result.found = true;
                    result.solution = suffix;
                    result.hash = hash;
                }
                
                // Periodically log progress
                if (m_detailedStats && attempts % 50000 == 0) {
                    logger.debug("Distribution solver: " + std::to_string(attempts) + " attempts");
                }
            }
            
            logger.info("Distribution solver completed with " + std::to_string(attempts) + " attempts");
            return result;
        }
        
        Result optimizedSolve(const std::string& challenge, int difficulty, std::atomic<bool>& should_stop) {
            logger.info("Using optimized approach for difficulty " + std::to_string(difficulty));
            
            // Use multiple threads with different character set strategies
            const int numThreads = std::max(1, (int)std::thread::hardware_concurrency());
            
            std::vector<std::thread> threads;
            std::atomic<bool> found(false);
            std::mutex resultMutex;
            Result finalResult;
            finalResult.found = false;
            
            for (int i = 0; i < numThreads; i++) {
                threads.emplace_back([this, i, &challenge, difficulty, &should_stop, &found, &resultMutex, &finalResult]() {
                    // Each thread uses a slightly different strategy
                    std::random_device rd;
                    std::mt19937 gen(rd() + i * 1000);
                    
                    // Choose character set based on thread ID
                    std::string charSet;
                    if (i % 3 == 0) {
                        charSet = Utils::getOptimizedCharSet();
                    } else if (i % 3 == 1) {
                        charSet = Utils::getBiasedCharSet();
                    } else {
                        charSet = Utils::getAlternativeCharSet();
                    }
                    
                    std::uniform_int_distribution<> dist(0, charSet.size() - 1);
                    
                    std::string suffix(m_suffixLength, '0');
                    uint64_t attempts = 0;
                    int localBestZeros = 0;
                    
                    while (!should_stop.load() && !found.load()) {
                        // Generate random suffix with thread-specific strategy
                        for (int j = 0; j < m_suffixLength; ++j) {
                            suffix[j] = charSet[dist(gen)];
                        }
                        
                        // Compute hash
                        std::string hash = Utils::sha1_evp(challenge + suffix);
                        attempts++;
                        
                        // Track best seen so far
                        int zeroCount = Utils::countLeadingZeros(hash);
                        if (zeroCount > localBestZeros) {
                            localBestZeros = zeroCount;
                            
                            if (m_detailedStats && zeroCount >= difficulty - 1) {
                                logger.debug("Thread " + std::to_string(i) + " found hash with " + 
                                            std::to_string(zeroCount) + " leading zeros: " + hash.substr(0, 16) + "...");
                            }
                        }
                        
                        // Check if it meets the target
                        if (hash.compare(0, difficulty, std::string(difficulty, '0')) == 0) {
                            std::lock_guard<std::mutex> lock(resultMutex);
                            if (!found.load()) {
                                found.store(true);
                                finalResult.found = true;
                                finalResult.solution = suffix;
                                finalResult.hash = hash;
                                logger.success("Thread " + std::to_string(i) + " found solution");
                            }
                            should_stop.store(true);
                            break;
                        }
                        
                        // Periodically log progress
                        if (m_detailedStats && attempts % 100000 == 0) {
                            logger.debug("Thread " + std::to_string(i) + " optimized solver: " + 
                                        std::to_string(attempts) + " attempts, best zeros: " + 
                                        std::to_string(localBestZeros));
                        }
                    }
                    
                    logger.debug("Thread " + std::to_string(i) + " completed with " + 
                               std::to_string(attempts) + " attempts");
                });
            }
            
            // Wait for all threads
            for (auto& thread : threads) {
                thread.join();
            }
            
            return finalResult;
        }
        
        int m_suffixLength;
        bool m_detailedStats;
    };
    
    // Main POW solver that orchestrates the different strategies
    static Result solve(const std::string& challenge, int difficulty, 
                      const std::string& strategy = "auto") {
        logger.header("Starting POW Solver");
        
        std::atomic<bool> should_stop(false);
        std::shared_ptr<SolverStrategy> solver;
        
        if (strategy == "cpu") {
            solver = std::make_shared<CPUThreadPoolStrategy>(
                config.powThreadCount,
                config.powBatchSize,
                config.powSuffixLength,
                config.detailedPowStats,
                config.powStatsInterval
            );
        }
#ifdef USE_OPENCL
        else if (strategy == "gpu") {
            solver = std::make_shared<GPUOpenCLStrategy>(
                0, 0, 64, 8192, 
                config.detailedPowStats,
                config.powStatsInterval
            );
        }
        else if (strategy == "hybrid") {
            std::vector<std::shared_ptr<SolverStrategy>> strategies;
            
            // Add CPU strategy
            strategies.push_back(std::make_shared<CPUThreadPoolStrategy>(
                config.powThreadCount,
                config.powBatchSize,
                config.powSuffixLength,
                config.detailedPowStats,
                config.powStatsInterval
            ));
            
            // Add GPU strategy
            strategies.push_back(std::make_shared<GPUOpenCLStrategy>(
                0, 0, 64, 8192, 
                config.detailedPowStats,
                config.powStatsInterval
            ));
            
            solver = std::make_shared<HybridStrategy>(strategies);
        }
#endif
        else if (strategy == "adaptive") {
            solver = std::make_shared<AdaptiveStrategy>(
                config.powSuffixLength,
                config.detailedPowStats
            );
        }
        else { // Auto - choose based on difficulty
            if (difficulty <= 5) {
                solver = std::make_shared<CPUThreadPoolStrategy>(
                    config.powThreadCount,
                    config.powBatchSize,
                    config.powSuffixLength,
                    config.detailedPowStats,
                    config.powStatsInterval
                );
            }
#ifdef USE_OPENCL
            else if (Utils::isGPUAvailable()) {
                logger.info("GPU detected, using hybrid strategy");
                std::vector<std::shared_ptr<SolverStrategy>> strategies;
                
                // Use both CPU and GPU for higher difficulties
                strategies.push_back(std::make_shared<CPUThreadPoolStrategy>(
                    config.powThreadCount / 2, // Use fewer CPU threads when GPU is also working
                    config.powBatchSize,
                    config.powSuffixLength,
                    config.detailedPowStats,
                    config.powStatsInterval
                ));
                
                strategies.push_back(std::make_shared<GPUOpenCLStrategy>(
                    0, 0, 64, 8192, 
                    config.detailedPowStats,
                    config.powStatsInterval
                ));
                
                solver = std::make_shared<HybridStrategy>(strategies);
            }
#endif
            else {
                solver = std::make_shared<AdaptiveStrategy>(
                    config.powSuffixLength,
                    config.detailedPowStats
                );
            }
        }
        
        auto startTime = std::chrono::high_resolution_clock::now();
        Result result = solver->solve(challenge, difficulty, should_stop);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
        
        logger.success("POW solving completed in " + std::to_string(duration) + " seconds");
        
        if (result.found) {
            // Verify the result
            std::string hash = Utils::sha1(challenge + result.solution);
            std::string expectedPrefix(difficulty, '0');
            
            if (hash.compare(0, difficulty, expectedPrefix) != 0) {
                logger.error("Solution verification failed! Hash: " + hash);
                result.found = false;
            } else {
                logger.success("Solution verified: " + result.solution);
                logger.success("Hash: " + hash);
            }
        } else {
            logger.warning("No solution found");
        }
        
        return result;
    }
};

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
        
        // Optimized character set (excluding disallowed characters)
        const std::string charSet = Utils::getOptimizedCharSet();
        std::uniform_int_distribution<> dist(0, charSet.size() - 1);
        
        // For improved efficiency, pre-allocate the suffix buffer
        std::string suffix(suffixLength, '0');
        
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
                // Generate random suffix (reuse buffer for less allocations)
                for (int j = 0; j < suffixLength; ++j) {
                    suffix[j] = charSet[dist(gen)];
                }
                
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
                        if (zeroCount >= m_difficulty - 1) {
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
    bool m_running;
    bool m_found;
    std::string m_solution;
    std::atomic<uint64_t> m_totalAttempts;
    int m_bestZeroCount;
    std::string m_bestHash;
    std::string m_bestSuffix;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_startTime;
};

#endif // POW_SOLVER_H