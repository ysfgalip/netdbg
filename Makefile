.PHONY: release dev clean

CC = gcc
SRC = $(wildcard src/*.c src/commands/*/*.c)
BUILD_DIR = build
OUT = netdbg
OUT_DEV = dev.o

release: 
	$(CC) -Wall -g $(SRC) -o $(BUILD_DIR)/$(OUT)

dev:
	$(CC) -Wall -g $(SRC) -o $(BUILD_DIR)/$(OUT_DEV)

clean:
	rm -f $(BUILD_DIR)/*
