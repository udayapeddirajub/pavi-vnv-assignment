# Makefile for the AES kernel module (Native Compilation)
# Placed in: driver/src/

MODULE_NAME := aes_driver

# The final object module name.
obj-m := $(MODULE_NAME).o

# Find 'aes_driver.h'.
ccflags-y := -I../inc

# KERNEL_H: The path to the kernel headers.
KERNEL_H ?= /lib/modules/$(shell uname -r)/build

# PWD: Get the current directory path (which is 'driver/src').
PWD := $(shell pwd)


# ---- Build Targets ----

# Default target: builds the module(s)
all:
	@echo "--- Building AES driver for native kernel [$(shell uname -r)] ---"
	$(MAKE) -C $(KERNEL_H) M=$(PWD) modules

# Clean target: removes all compiled files
clean:
	@echo "--- Cleaning up AES driver ---"
	$(MAKE) -C $(KERNEL_H) M=$(PWD) clean
