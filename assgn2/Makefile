CFLAGS =	-g -std=c++11 -Wall -lpcap

all:
	g++ $(CFLAGS) balancer.cpp -o balancer

debugparse:
	g++ $(CFLAGS) -DDEBUGPARSE balancer.cpp -o balancer

clean:
	rm -rf balancer *.dSYM .DS_Store
