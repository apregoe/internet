CC = g++
CFLAGS = -std=c++0x -g -Wall
CDEBUG = -DDEBUG
EXEC = server client *.dSYM

all: server client

server: server.cpp
	$(CC) $(CFLAGS) $@.cpp -o $@

client: client.cpp
	$(CC) $(CFLAGS) $@.cpp -o $@

clean:
	rm -rf $(EXEC)
