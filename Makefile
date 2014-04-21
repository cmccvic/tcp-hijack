PROGRAM = sniffer
CC = gcc
CFLAGS = -Wall -Werror -lpcap
SRC = spdcx-sniff.c

all:	sniffer

sniffer: $(SRC) 
	mkdir -p dist
	$(CC) $(CFLAGS) -o dist/$(PROGRAM) $(SRC)

clean:
	mkdir -p dist
	rm -rf dist/*