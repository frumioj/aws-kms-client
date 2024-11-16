# Compiler and flags
CC = gcc
CFLAGS = -I./include -Wall -Wextra -g
LDFLAGS = -lcurl -ljson-c -lcrypto

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN = $(BUILD_DIR)/kms_example

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Default target
all: $(BUILD_DIR) $(BIN)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Link the final binary
$(BIN): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(BIN) $(LDFLAGS)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -rf $(BUILD_DIR)

# Run target
run: all
	$(BIN)

.PHONY: all clean run
