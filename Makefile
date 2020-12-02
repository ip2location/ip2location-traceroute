CC = gcc
CFLAGS = -std=c99 -Wall -Wextra
LIBS = -l IP2Location

all: ipltrace
ipltrace: src/main.o src/trace.o src/error.o
	$(CC) $(CFLAGS) $(LIBS) -o ipltrace $^
main.o: src/trace.h
trace.o: src/trace.h src/error.h
error.o: src/error.h

clean:
	rm -f src/*.o
distclean:
	rm -f src/*.o
	rm -f ipltrace

install:
	cp ./ipltrace /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/ipltrace