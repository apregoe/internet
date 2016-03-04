CFLAGS =	-g -std=c++0x -Wall -lpcap

all:
	g++ $(CFLAGS) balancer.cpp -o balancer

debugparse:
	g++ $(CFLAGS) -DDEBUGPARSE balancer.cpp -o balancer

debugdbo:#DBO = data base outout
	g++ $(CFLAGS) -DDBO balancer.cpp -o balancer

debugbalancer:#DEBUGBALANCER
	g++ $(CFLAGS) -DDEBUGBALANCER balancer.cpp -o balancer

debugprobability:#DEBUGPROBABILITY
	g++ $(CFLAGS) -DDEBUGPROBABILITY balancer.cpp -o balancer

clean:
	rm -rf balancer *.dSYM .DS_Store logfile.txt sniff webserver.*
