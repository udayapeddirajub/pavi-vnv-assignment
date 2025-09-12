# Makefile for the AES user-space application
# Placed in: software/src/

# Compiler and flags
CC := gcc
# Tell GCC where to find our (aes_app.h)
CFLAGS := -Wall -Wextra -std=c99 -g -I../inc

# Source files and executable name
SRCS := aes_app.c
TARGET := aes_app

# Default target: builds the application
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

# Clean target: removes the executable
clean:
	rm -f $(TARGET)

# Install target: (optional) copies the app to a system binary path
install: all
	sudo cp $(TARGET) /usr/local/bin
