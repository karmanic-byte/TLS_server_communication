CXX = g++
CXXFLAGS = -Wall -Wextra -g3 -O3 -std=c++17
LDFLAGS = -lssl -lcrypto -lws2_32 -pthread

# Output directory
OUTPUT_DIR = output
# Source files
SRCS = main.cpp logger.cpp config.cpp
# Object files
OBJS = $(patsubst %.cpp,$(OUTPUT_DIR)/%.o,$(SRCS))
# Executable name
EXEC = $(OUTPUT_DIR)/optimized_tls_client.exe

.PHONY: all clean

all: $(OUTPUT_DIR) $(EXEC)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

$(EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OUTPUT_DIR)/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT_DIR)

# Dependencies
$(OUTPUT_DIR)/main.o: main.cpp utils.h logger.h config.h pow_solver.h tls_connection.h exatest_client.h
$(OUTPUT_DIR)/logger.o: logger.cpp logger.h utils.h
$(OUTPUT_DIR)/config.o: config.cpp config.h logger.h utils.h
