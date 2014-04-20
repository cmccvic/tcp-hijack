.PHONY: all tcphijack clean run

all:
	cd src; make

tcphijack:
	cd src; make tcphijack

run:
	cd src; make run

clean:
	cd src; make clean
