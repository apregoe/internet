CFLAGS =	-g -std=c++11 -Wall -lpcap

all:
	g++ $(CFLAGS) balancer.cpp -o balancer

debugparse:
	g++ $(CFLAGS) -DDEBUGPARSE balancer.cpp -o balancer

debugdbo:#DBO = data base outout
	g++ $(CFLAGS) -DDBO balancer.cpp -o balancer

clean:
	rm -rf balancer *.dSYM .DS_Store
