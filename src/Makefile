CC = gcc
INCLUDES = -I../include
CFLAGS = -Wall -Werror $(INCLUDES)
LIBS = -lpcap
BIN = tcphijack

.PHONY: clean all run

all: tcphijack

tcphijack:	tcphijack.o
	$(CC) $(CFLAGS) -o $(BIN) *.o

tcphijack.o: tcphijack.c
	$(CC) $(CFLAGS) -c $*.c $(LIBS)

run: tcphijack
	sudo ./$(BIN)

clean:
	rm -f *.o $(BIN)