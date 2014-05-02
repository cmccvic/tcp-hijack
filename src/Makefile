CC = gcc
INCLUDES = -I../include
CFLAGS = -Wall -Werror $(INCLUDES)
LIBS = -lpcap
BIN = tcp-disrupt
DIST = ../dist

.PHONY: clean all run

all: tcp-disrupt

tcp-disrupt: tcp-disrupt.o packet-send.o packet-sniff.o
	mkdir -p $(DIST);
	$(CC) $(CFLAGS) -o $(DIST)/$(BIN) ../src/packet-send.o ../src/tcp-disrupt.o ../src/packet-sniff.o $(LIBS)

tcp-disrupt.o: tcp-disrupt.c ../include/tcp-disrupt.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)	

packet-sniff.o: packet-sniff.c ../include/packet-sniff.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)		

packet-send.o: packet-send.c ../include/packet-send.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)

run: tcp-disrupt
	sudo ./$(DIST)/$(BIN)

clean:
	rm -f *.o *.out
	rm -rf $(DIST)
