.PHONY: all tcp-disrupt clean run

all:
	cd src; make

tcp-disrupt:
	cd src; make tcp-disrupt

run:
	cd src; make run

clean:
	cd src; make clean
