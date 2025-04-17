# Compiler settings
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -O3 -march=native
LDFLAGS = -lssl -lcrypto -pthread

# For Windows (MinGW/MSYS)
ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32
endif

# OpenCL support (optional)
USE_OPENCL ?= 0
ifeq ($(USE_OPENCL),1)
    CXXFLAGS += -DUSE_OPENCL
    LDFLAGS += -lOpenCL
endif

# Source files - check your actual extensions (.cpp or .cc)
SRC_EXT = cpp
SOURCES = main.$(SRC_EXT) config.$(SRC_EXT) logger.$(SRC_EXT)

# Object files
OBJECTS = $(SOURCES:.$(SRC_EXT)=.o)

# Output directories
BUILDDIR = build
BINDIR = bin

# Executable name
ifeq ($(OS),Windows_NT)
    TARGET = $(BINDIR)/exatest_client.exe
else
    TARGET = $(BINDIR)/exatest_client
endif

# Default target
all: directories release

# Create directories
directories:
	mkdir -p $(BUILDDIR)
	mkdir -p $(BINDIR)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: directories $(TARGET)

# Release build
release: CXXFLAGS += -O3 -DNDEBUG
release: directories $(TARGET)

# Profile build for performance analysis
profile: CXXFLAGS += -pg -DNDEBUG
profile: LDFLAGS += -pg
profile: directories $(TARGET)

# Build target
$(TARGET): $(addprefix $(BUILDDIR)/,$(OBJECTS))
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $@"

# Copy your existing files to build directory first, then compile
$(BUILDDIR)/%.o: %.$(SRC_EXT)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -rf $(BUILDDIR)
	rm -rf $(BINDIR)

# List all files in current directory
list:
	@echo "Files in current directory:"
	@ls -la

# Check system info
check:
	@echo "C++ Compiler: $(CXX)"
	@echo "OpenCL Support: $(USE_OPENCL)"
	@echo "Source extension: $(SRC_EXT)"
	@echo "Looking for files: $(SOURCES)"
	@$(CXX) --version

# Build with GPU support
gpu: USE_OPENCL=1
gpu: release

# Phony targets
.PHONY: all clean directories debug release profile check gpu list