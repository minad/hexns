#CC=clang
CC=gcc

all: test

hexns: hexns.c Makefile
	$(CC) -lidn -g -std=c11 -Wall -o $@ $<

test: hexns
	@./test.sh
