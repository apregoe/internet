CC = g++
CFLAGS = -std=c++0x -g -Wall -lpcap -lpthread

CDEBUG = -DDEBUG
EXEC = desman watchdog *.dSYM

all: desman watchdog

desman: desman.cpp
	$(CC) $(CFLAGS) $@.cpp -o $@

watchdog: watchdog.cpp
	$(CC) $(CFLAGS) $@.cpp -o $@

clean:
	rm -rf *.txt $(EXEC)
