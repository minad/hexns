CC=clang

all: test

hexns: hexns.c
	$(CC) -g -std=c11 -Wall -o $@ $<

test: hexns
	./test.sh