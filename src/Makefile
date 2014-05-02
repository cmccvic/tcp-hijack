CC = gcc
INCLUDES = -I../include
CFLAGS = -Wall -Werror $(INCLUDES)
LIBS = -lpcap
BIN = tcp-disrupt
DIST = ../dist

.PHONY: clean all run

all: tcp-disrupt

tcp-disrupt: tcp-disrupt.o tcphijack.o packet-sniff.o
	mkdir -p $(DIST);
	$(CC) $(CFLAGS) -o $(DIST)/$(BIN) ../src/tcphijack.o ../src/tcp-disrupt.o ../src/packet-sniff.o $(LIBS)

tcp-disrupt.o: tcp-disrupt.c ../include/tcp-disrupt.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)	

packet-sniff.o: packet-sniff.c ../include/packet-sniff.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)		

tcphijack.o: tcphijack.c ../include/tcphijack.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)

run: tcphijack
	sudo ./$(BIN)

clean:
	rm -f *.o *.out
	rm -rf $(DIST)
