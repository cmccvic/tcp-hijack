CC = gcc
CFLAGS = -Wall -Werror
LIBS = -lpcap
BIN = tcphijack

all: tcphijack

tcphijack:	tcphijack.o
	$(CC) $(CFLAGS) -o $(BIN) *.o

tcphijack.o: tcphijack.c
	$(CC) $(CFLAGS) -c $*.c $(LIBS)

run: tcphijack
	sudo ./$(BIN)

clean:
	rm -f *.o $(BIN)