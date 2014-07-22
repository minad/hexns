#CC=clang
CC=gcc
CFLAGS=-g -std=c11 -Wall
#CFLAGS=-O3 -std=c11 -Wall

all: hexns dnsforward

hexns: hexns.c Makefile
	$(CC) $(CFLAGS) -lidn -o $@ $<

dnsforward: dnsforward.c Makefile
	$(CC) $(CFLAGS) -o $@ $<

test: hexns
	@./test.sh
