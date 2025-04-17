#ifndef OPENCL_UTILS_H
#define OPENCL_UTILS_H

#include <string>
#include <vector>
#include <CL/cl.h>
#include <stdexcept>
#include <sstream>
#include "logger.h"

namespace OpenCLUtils {

// Class to manage OpenCL context and resources
class Context {
public:
    Context(int platformIndex = 0, int deviceIndex = 0) {
        cl_int error;
        
        // Get platforms
        cl_uint platformCount;
        error = clGetPlatformIDs(0, nullptr, &platformCount);
        if (error != CL_SUCCESS || platformCount == 0) {
            throw std::runtime_error("Failed to get OpenCL platform count");
        }
        
        std::vector<cl_platform_id> platforms(platformCount);
        error = clGetPlatformIDs(platformCount, platforms.data(), nullptr);
        if (error != CL_SUCCESS) {
            throw std::runtime_error("Failed to get OpenCL platforms");
        }
        
        // Bounds check for platform index
        if (platformIndex >= static_cast<int>(platformCount)) {
            platformIndex = 0;
        }
        
        // Get selected platform
        m_platform = platforms[platformIndex];
        
        // Get devices
        cl_uint deviceCount;
        error = clGetDeviceIDs(m_platform, CL_DEVICE_TYPE_ALL, 0, nullptr, &deviceCount);
        if (error != CL_SUCCESS || deviceCount == 0) {
            throw std::runtime_error("Failed to get OpenCL device count");
        }
        
        std::vector<cl_device_id> devices(deviceCount);
        error = clGetDeviceIDs(m_platform, CL_DEVICE_TYPE_ALL, deviceCount, devices.data(), nullptr);
        if (error != CL_SUCCESS) {
            throw std::runtime_error("Failed to get OpenCL devices");
        }
        
        // Bounds check for device index
        if (deviceIndex >= static_cast<int>(deviceCount)) {
            deviceIndex = 0;
        }
        
        // Get selected device
        m_device = devices[deviceIndex];
        
        // Create context
        m_context = clCreateContext(nullptr, 1, &m_device, nullptr, nullptr, &error);
        if (error != CL_SUCCESS) {
            throw std::runtime_error("Failed to create OpenCL context");
        }
        
        // Create command queue
        m_commandQueue = clCreateCommandQueue(m_context, m_device, 0, &error);
        if (error != CL_SUCCESS) {
            clReleaseContext(m_context);
            throw std::runtime_error("Failed to create OpenCL command queue");
        }
    }
    
    ~Context() {
        if (m_commandQueue) {
            clReleaseCommandQueue(m_commandQueue);
        }
        if (m_context) {
            clReleaseContext(m_context);
        }
    }
    
    cl_context getContext() const {
        return m_context;
    }
    
    cl_command_queue getCommandQueue() const {
        return m_commandQueue;
    }
    
    cl_device_id getDevice() const {
        return m_device;
    }
    
    std::string getDeviceName() const {
        char deviceName[256] = {0};
        clGetDeviceInfo(m_device, CL_DEVICE_NAME, sizeof(deviceName), deviceName, nullptr);
        return std::string(deviceName);
    }
    
private:
    cl_platform_id m_platform;
    cl_device_id m_device;
    cl_context m_context;
    cl_command_queue m_commandQueue;
};

// Build an OpenCL program
inline cl_program buildProgram(cl_context context, cl_device_id device, const std::string& source) {
    cl_int error;
    
    const char* sourceCStr = source.c_str();
    size_t sourceLength = source.length();
    
    cl_program program = clCreateProgramWithSource(context, 1, &sourceCStr, &sourceLength, &error);
    if (error != CL_SUCCESS) {
        throw std::runtime_error("Failed to create OpenCL program");
    }
    
    error = clBuildProgram(program, 1, &device, nullptr, nullptr, nullptr);
    if (error != CL_SUCCESS) {
        // Get build log
        size_t logSize;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &logSize);
        
        std::vector<char> log(logSize);
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, logSize, log.data(), nullptr);
        
        std::string errorMsg = "Failed to build OpenCL program: " + std::string(log.data());
        clReleaseProgram(program);
        throw std::runtime_error(errorMsg);
    }
    
    return program;
}

// Get SHA-1 kernel source for POW solving
inline std::string getHashKernelSource() {
    return R"(
        // SHA-1 implementation based on RFC 3174
        #define SHA1_BLOCK_SIZE 64
        #define SHA1_DIGEST_SIZE 20
        
        typedef struct {
            uint state[5];
            ulong count;
            uchar buffer[SHA1_BLOCK_SIZE];
        } SHA1_CTX;
        
        #define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
        #define BLK(i) (block->l[i&15] = ROL(block->l[(i+13)&15] ^ block->l[(i+8)&15] ^ block->l[(i+2)&15] ^ block->l[i&15],1))
        
        typedef union {
            uchar c[64];
            uint l[16];
        } CHAR64LONG16;
        
        void SHA1Transform(uint state[5], const uchar buffer[64]) {
            uint a, b, c, d, e;
            CHAR64LONG16 block[1];
            
            memcpy(block, buffer, 64);
            
            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            
            // Round 1
            #define R1(v,w,x,y,z,i) z += ((w&(x^y))^y) + block->l[i] + 0x5A827999 + ROL(v,5); w = ROL(w,30);
            R1(a,b,c,d,e, 0); R1(e,a,b,c,d, 1); R1(d,e,a,b,c, 2); R1(c,d,e,a,b, 3);
            R1(b,c,d,e,a, 4); R1(a,b,c,d,e, 5); R1(e,a,b,c,d, 6); R1(d,e,a,b,c, 7);
            R1(c,d,e,a,b, 8); R1(b,c,d,e,a, 9); R1(a,b,c,d,e,10); R1(e,a,b,c,d,11);
            R1(d,e,a,b,c,12); R1(c,d,e,a,b,13); R1(b,c,d,e,a,14); R1(a,b,c,d,e,15);
            
            // Round 2
            #define R2(v,w,x,y,z,i) z += ((w&(x^y))^y) + BLK(i) + 0x5A827999 + ROL(v,5); w = ROL(w,30);
            R2(e,a,b,c,d,16); R2(d,e,a,b,c,17); R2(c,d,e,a,b,18); R2(b,c,d,e,a,19);
            
            // Round 3
            #define R3(v,w,x,y,z,i) z += (w^x^y) + BLK(i) + 0x6ED9EBA1 + ROL(v,5); w = ROL(w,30);
            R3(a,b,c,d,e,20); R3(e,a,b,c,d,21); R3(d,e,a,b,c,22); R3(c,d,e,a,b,23);
            R3(b,c,d,e,a,24); R3(a,b,c,d,e,25); R3(e,a,b,c,d,26); R3(d,e,a,b,c,27);
            R3(c,d,e,a,b,28); R3(b,c,d,e,a,29); R3(a,b,c,d,e,30); R3(e,a,b,c,d,31);
            R3(d,e,a,b,c,32); R3(c,d,e,a,b,33); R3(b,c,d,e,a,34); R3(a,b,c,d,e,35);
            
            // Round 4
            #define R4(v,w,x,y,z,i) z += (((w|x)&y)|(w&x)) + BLK(i) + 0x8F1BBCDC + ROL(v,5); w = ROL(w,30);
            R4(e,a,b,c,d,36); R4(d,e,a,b,c,37); R4(c,d,e,a,b,38); R4(b,c,d,e,a,39);
            R4(a,b,c,d,e,40); R4(e,a,b,c,d,41); R4(d,e,a,b,c,42); R4(c,d,e,a,b,43);
            R4(b,c,d,e,a,44); R4(a,b,c,d,e,45); R4(e,a,b,c,d,46); R4(d,e,a,b,c,47);
            R4(c,d,e,a,b,48); R4(b,c,d,e,a,49); R4(a,b,c,d,e,50); R4(e,a,b,c,d,51);
            R4(d,e,a,b,c,52); R4(c,d,e,a,b,53); R4(b,c,d,e,a,54); R4(a,b,c,d,e,55);
            
            // Round 5
            #define R5(v,w,x,y,z,i) z += (w^x^y) + BLK(i) + 0xCA62C1D6 + ROL(v,5); w = ROL(w,30);
            R5(e,a,b,c,d,56); R5(d,e,a,b,c,57); R5(c,d,e,a,b,58); R5(b,c,d,e,a,59);
            R5(a,b,c,d,e,60); R5(e,a,b,c,d,61); R5(d,e,a,b,c,62); R5(c,d,e,a,b,63);
            R5(b,c,d,e,a,64); R5(a,b,c,d,e,65); R5(e,a,b,c,d,66); R5(d,e,a,b,c,67);
            R5(c,d,e,a,b,68); R5(b,c,d,e,a,69); R5(a,b,c,d,e,70); R5(e,a,b,c,d,71);
            R5(d,e,a,b,c,72); R5(c,d,e,a,b,73); R5(b,c,d,e,a,74); R5(a,b,c,d,e,75);
            
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }
        
        void SHA1Init(SHA1_CTX* context) {
            context->state[0] = 0x67452301;
            context->state[1] = 0xEFCDAB89;
            context->state[2] = 0x98BADCFE;
            context->state[3] = 0x10325476;
            context->state[4] = 0xC3D2E1F0;
            context->count = 0;
        }
        
        void SHA1Update(SHA1_CTX* context, const uchar* data, uint len) {
            uint i, j;
            
            j = context->count & 63;
            context->count += len;
            
            if ((j + len) > 63) {
                memcpy(&context->buffer[j], data, (i = 64 - j));
                SHA1Transform(context->state, context->buffer);
                for (; i + 63 < len; i += 64) {
                    SHA1Transform(context->state, &data[i]);
                }
                j = 0;
            } else {
                i = 0;
            }
            memcpy(&context->buffer[j], &data[i], len - i);
        }
        
        void SHA1Final(uchar digest[20], SHA1_CTX* context) {
            ulong i, j;
            uchar finalcount[8];
            
            for (i = 0; i < 8; i++) {
                finalcount[i] = (uchar)((context->count >> ((7 - (i & 7)) * 8)) & 255);
            }
            
            SHA1Update(context, (uchar *)"\200", 1);
            while ((context->count & 63) != 56) {
                SHA1Update(context, (uchar *)"\0", 1);
            }
            SHA1Update(context, finalcount, 8);
            
            for (i = 0; i < 20; i++) {
                digest[i] = (uchar)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
            }
        }
        
        // Convert a byte to a hex char
        uchar byteToHexChar(uchar b, bool upper) {
            if (b < 10)
                return '0' + b;
            return (upper ? 'A' : 'a') + (b - 10);
        }
        
        // Hex char lookup table for faster conversion
        __constant uchar hexChars[16] = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };
        
        // Convert digest to hex string
        void digestToHex(const uchar digest[20], char hexOutput[41]) {
            for (int i = 0; i < 20; i++) {
                uchar b = digest[i];
                hexOutput[i*2] = hexChars[b >> 4];
                hexOutput[i*2+1] = hexChars[b & 0xF];
            }
            hexOutput[40] = '\0';
        }
        
        // Character set for POW suffixes (excluding disallowed chars)
        __constant char allowedChars[] = 
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        
        __constant int allowedCharsLen = 94; // Length of the above array
        
        // Check if a hash starts with the required number of zeros
        bool hasLeadingZeros(const char* hexHash, int zeros) {
            for (int i = 0; i < zeros; i++) {
                if (hexHash[i] != '0') {
                    return false;
                }
            }
            return true;
        }
        
        // Hash function for string
        void hashString(const char* str, uint length, char* hashOutput) {
            SHA1_CTX context;
            uchar digest[20];
            
            SHA1Init(&context);
            SHA1Update(&context, (uchar*)str, length);
            SHA1Final(digest, &context);
            
            digestToHex(digest, hashOutput);
        }
        
        // Deterministic random number generator
        uint xorshift(uint* state) {
            uint x = *state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *state = x;
            return x;
        }
        
        // Main kernel for POW search
        __kernel void sha1_search(
            __global const char* challenge,
            const int challengeLen,
            const int difficulty,
            __global char* output,
            __global int* found,
            const ulong seed
        ) {
            int id = get_global_id(0);
            
            // Initialize random state based on global ID and seed
            uint state = id ^ (seed & 0xFFFFFFFF) ^ ((seed >> 32) & 0xFFFFFFFF);
            
            // Skip a few iterations to increase randomness
            for (int i = 0; i < 10; i++) {
                xorshift(&state);
            }
            
            // Generate a random suffix (8 characters)
            const int suffixLen = 8;
            char suffix[9];
            
            for (int i = 0; i < suffixLen; i++) {
                uint random = xorshift(&state);
                suffix[i] = allowedChars[random % allowedCharsLen];
            }
            suffix[suffixLen] = '\0';
            
            // Create the full string to hash (challenge + suffix)
            char fullString[1024]; // Assuming challenge + suffix will fit
            
            // Copy challenge
            for (int i = 0; i < challengeLen; i++) {
                fullString[i] = challenge[i];
            }
            
            // Append suffix
            for (int i = 0; i < suffixLen; i++) {
                fullString[challengeLen + i] = suffix[i];
            }
            
            // Compute hash
            char hashOutput[41]; // SHA-1 hex is 40 chars + null terminator
            hashString(fullString, challengeLen + suffixLen, hashOutput);
            
            // Check if we found a solution
            if (hasLeadingZeros(hashOutput, difficulty)) {
                // Atomically check and set found flag
                if (atomic_cmpxchg(found, 0, 1) == 0) {
                    // We're the first to find a solution, copy to output
                    for (int i = 0; i < suffixLen; i++) {
                        output[i] = suffix[i];
                    }
                    output[suffixLen] = '\0';
                }
            }
        }
    )";
}

} // namespace OpenCLUtils

#endif // OPENCL_UTILS_H