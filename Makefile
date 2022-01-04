CC = gcc
LIBS = -l IP2Location

all: ip2trace
ip2trace: src/main.o src/trace.o
	$(CC) -o ip2trace $^ $(LIBS)

main.o: src/trace.h
trace.o: src/trace.h

clean:
	rm -f src/*.o

distclean:
	rm -f src/*.o
	rm -f ip2trace

install:
	cp ./ip2trace /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/ip2trace