CC=clang
hexns: hexns.c
	$(CC) -g -std=c11 -Wall -o $@ $<
