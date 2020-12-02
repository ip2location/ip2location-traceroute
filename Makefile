CC = gcc
CFLAGS = -std=c99 -Wall -Wextra
LIBS = -l IP2Location

all: ip2trace
ip2trace: src/main.o src/trace.o src/error.o
	$(CC) $(CFLAGS) $(LIBS) -o ip2trace $^
main.o: src/trace.h
trace.o: src/trace.h src/error.h
error.o: src/error.h

clean:
	rm -f src/*.o
distclean:
	rm -f src/*.o
	rm -f ip2trace

install:
	cp ./ip2trace /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/ip2trace