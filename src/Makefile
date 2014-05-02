CC = gcc
INCLUDES = -I../include
CFLAGS = -Wall -Werror $(INCLUDES)
LIBS = -lpcap
BIN = tcphijack

.PHONY: clean all run

all: tcphijack

tcphijack:	tcphijack.o
	$(CC) $(CFLAGS) -o $(BIN) tcphijack.o

tcphijack.o: tcphijack.c ../include/tcphijack.h
	$(CC) $(CFLAGS) -c $*.c $(LIBS)

run: tcphijack
	sudo ./$(BIN)

clean:
	rm -f *.o *.out $(BIN)
