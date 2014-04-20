CC = gcc
CFLAGS =- Wall -Werror
LIBS = -lpcap

all: hijack

hijack:	tcphighjack.o tcphighjack.h
	$(CC) $(CFLAGS) -o highjack $*.o $(LIBS)

hijack.o: tcphighjack.c tcphighjack.h
	$(CC) $(CFLAGS) -c $*.c

run:
	sudo ./highjack

clean:
	rm -f *.o highjack