#include "sniff.h"// taken from http://www.tcpdump.org/pcap.html

#include <iostream>
#include <string>

#include <pcap.h>

#include <arpa/inet.h>

//compile-time definitions
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

//Global variables
/*
sudo ./balancer -r pcapSamples/udp-multipleIP-6.pcap -i en0 -l logfile.txt -p -b
*/
//user input
std::string filename, logfile, interface;
bool p, b, s, d;//flags


//func signatures
bool parseInput(int argv, char** argc);//parses input
void printParsedResults();//prints results
void got_packet(const pcap_pkthdr *header, const u_char *packet);

int main(int argv, char** argc) {
    p = b = s = d = false;
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    bpf_program fp;//compiled version of our filter
    bpf_u_int32 mask;//The netmask of our sniffing device
    bpf_u_int32 net;//The IP of our sniffing device
    pcap_pkthdr header;//header of the received packet
    const u_char* packet = NULL;//packet received

    if(!parseInput(argv, argc)){
        std::cout << "usage: ./balancer [-r filename] [-i interface] [ -l filename ] " <<
                        "[-p] [-b] [-s] [-d] \n or \n" <<
                        "./balancer [-r filename] [-i interface] " <<
                        "[-w num] [ -l filename ] [-c configpercent]" << std::endl;
        return 1;
    }

    //getting network from mask and interface
    if(pcap_lookupnet(interface.c_str(), &net, &mask, errBuff) == -1){
        std::cerr << "Problem in funct pcap_lookupnet: " << errBuff << std::endl << strerror(errno) << std::endl;
        return 1;
    }

    //opening pcap in which we will sniff
    if((handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errBuff)) == NULL){
        std::cerr << "Problem in funct pcap_open_live: " << errBuff << std::endl << strerror(errno) << std::endl;
        return 1;
    }

    //verifying correct data link
    if(pcap_datalink(handle) != DLT_EN10MB){
        std::cerr << "Problem in funct pcap_datalink: " << errBuff << std::endl << strerror(errno) << std::endl;
        return 1;
    }

    //compile version
    if(pcap_compile(handle, &fp, "ip", 0, net) == -1){
        std::cerr << "Problem in funct pcap_compile: " << errBuff << std::endl << strerror(errno) << std::endl;
        return 1;
    }

    //seting up filter
    /*if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Problem in funct pcap_setfilter: " << errBuff << std::endl << strerror(errno) << std::endl;
        return 1;
    }*/

    //looping through every packet the sniff device gets
    //get_packet is the call back function
    while(true){
        packet = pcap_next(handle, &header);
        got_packet(&header, packet);
    }
    pcap_close(handle);

    return 0;
}

void got_packet(const pcap_pkthdr *header, const u_char *packet){

    const sniff_ethernet *ethernet; /* The ethernet header */
    const sniff_ip *ip; /* The IP header */
    const sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    if(packet == NULL){
        std::cout << "returning" << std::endl;
        return;
    }

    //casting the packet
    ethernet = (sniff_ethernet*)packet;
    ip = (sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        //std::cerr << "Problem in funct get_packet, out in size_ip. \n invalid size_ip.";
        return;
    }
    tcp = (sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        //std::cerr << "Problem in funct get_packet, out in size_tcp. \n invalid size_tcp.";
        return;
    }
    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);


    std::cout << "From: " << inet_ntoa(ip->ip_src) << std::endl;
    std::cout << "To:   " << inet_ntoa(ip->ip_dst) << std::endl;
    std::cout << "Size: " << header->len << std:: endl << std::endl;

}

bool parseInput(int argv, char** argc){
    #if DEBUGPARSE
        for(int i = 0; i < argv; ++i){
            std::cout << *(argc+i) << " " << std::endl;
        }
    #endif

    if(argv == 1){
        return false;
    }

    int flagsCount = 0;


    #if DEBUGPARSE
        std::cout << "inside parseInput()" << std::endl;
    #endif
        for(int i = 1; i < argv; ++i){
            #if DEBUGPARSE
                std::cout << "argc[" << i << "]: " << argc[i] << std:: endl;
                std::cout << "-r " << strcmp(argc[i], "-r") << std::endl;
                std::cout << "-i " << strcmp(argc[i], "-i") << std::endl;
                std::cout << "-l " << strcmp(argc[i], "-l") << std::endl;
                std::cout << "-p " << strcmp(argc[i], "-p") << std::endl;
                std::cout << "-b " << strcmp(argc[i], "-b") << std::endl;
                std::cout << "-s " << strcmp(argc[i], "-s") << std::endl;
                std::cout << "-d " << strcmp(argc[i], "-d") << std::endl;
            #endif
            if(strcmp(argc[i], "-r") == 0){
                filename = std::string(argc[++i]);
                #if DEBUGPARSE
                    std::cout << "filename " << filename << std:: endl;
                #endif
                continue;
            }else if(strcmp(argc[i], "-i") == 0){
                interface = std::string(argc[++i]);
                #if DEBUGPARSE
                    std::cout << "interface " << interface << std:: endl;
                #endif
                continue;
            }else if(strcmp(argc[i], "-l") == 0){
                logfile = std::string(argc[++i]);
                #if DEBUGPARSE
                    std::cout << "logfile " << logfile << std:: endl;
                #endif
                continue;
            }else if(strcmp(argc[i], "-p") == 0){
                p = true;
                ++flagsCount;
                #if DEBUGPARSE
                    std::cout << "-p = true" << argc[i] << std:: endl;
                #endif
                continue;
            }else if(strcmp(argc[i], "-b") == 0){
                b = true;
                ++flagsCount;
                #if DEBUGPARSE
                    std::cout << "-b = true" << argc[i] << std:: endl;
                #endif
                continue;
            }else if(strcmp(argc[i], "-s") == 0){
                s = true;
                ++flagsCount;
                #if DEBUGPARSE
                    std::cout << "-s = true: " << std:: endl;
                #endif
                continue;
            }else if (strcmp(argc[i], "-d") == 0){
                d = true;
                ++flagsCount;
                #if DEBUGPARSE
                    std::cout << "-d = true" << argc[i] << std:: endl;
                #endif
                continue;
            }else{
                std::cout << "unknown command: " << argc[i] << std::endl;
                return false;
            }
        }
        if(flagsCount == 0){
            return false;
        }
        #if DEBUGPARSE
            printParsedResults();
        #endif
        return true;
}


void printParsedResults(){
    std::cout << "filename = " << filename << std::endl;
    std::cout << "logfile = " << logfile << std::endl;
    std::cout << "interface = " << interface << std::endl;
    std::cout << "p = " << p << std::endl;
    std::cout << "b = " << b << std::endl;
    std::cout << "s = " << s << std::endl;
    std::cout << "d = " << d << std::endl;
}
