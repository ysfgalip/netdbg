.PHONY: dev

CC = gcc
SRC = src/*
OUT = build/dev.o

dev:
	$(CC) -Wall -g $(SRC) -o $(OUT) 

