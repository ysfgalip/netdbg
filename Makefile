.PHONY: dev

CC = gcc
SRC = src/*
OUT = build/dev

dev:
	$(CC) -Wall -g $(SRC) -o $(OUT) 

