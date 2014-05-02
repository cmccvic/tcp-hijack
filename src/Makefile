CC = gcc
INCLUDES = -I../include
CFLAGS = -Wall -Werror -E $(INCLUDES)
LIBS = -lpcap
BIN = tcphijack

.PHONY: clean all run

all: tcphijack

tcphijack:	tcphijack.o tcp-disrupt.o
	$(CC) $(CFLAGS) -o $(BIN) tcphijack.o tcp-disrupt.o

tcp-disrupt.o: tcp-disrupt.c ../include/tcp-disrupt.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)	

packet-sniff.o: packet-sniff.c ../include/packet-sniff.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)		

tcphijack.o: tcphijack.c ../include/tcphijack.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)

run: tcphijack
	sudo ./$(BIN)

clean:
	rm -f *.o *.out $(BIN)
