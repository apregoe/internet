#include "sniff.h"// taken from http://www.tcpdump.org/pcap.html

#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <string>

#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

//compile-time definitions
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define MAX_COLUMNS 4
#define SEPARATOR " "

//Global variables
/*
./balancer -i en0 -l logfile.txt -s -d -p -b
./balancer -r pcapSamples/tcp-twoIP-200.pcap -l logfile.txt -s -d -p -b

./balancer -r pcapSamples/tcp-twoIP-200.pcap -w 2 -c 50:50 -l logfile.txt
*/

//sniffing variables. I made them global since I use most of them in different functions
char errBuff[PCAP_ERRBUF_SIZE];
pcap_t* handle = NULL;
bpf_program fp;//compiled version of our filter
bpf_u_int32 mask;//The netmask of our sniffing device
bpf_u_int32 net;//The IP of our sniffing device
pcap_pkthdr header;//header of the received packet
const u_char* packet = NULL;//packet received

//user input
std::string filename, logfile, interface, configpercent;
int num;
bool r, i, w, p, b, c, s, d;//flags
bool balancer, sniffer;//

//database
//table part one
std::unordered_map<std::string, int > db_bytesCount;
std::unordered_map<std::string, int > db_packetCount;
std::string firstRow[4];
//database constants
const std::string PACKET = "Packets";
const std::string BYTES  = "Bytes";
const std::string SRC    = "Source";
const std::string DST    = "Destination";

//table part two
std::unordered_map<std::string, const int> db_flow;//each flow will be assing a server (randomly)
int pktIndex = 0;//packet number that is being sniffed




//func signatures
bool parseInput(int argv, char** argc);//parses input
void printParsedResults();//prints results
void got_packet(const pcap_pkthdr *header, const u_char *packet, int & pktIndex);
void exit_signal(int signal);//function called when Ctr+C
void dump_UDP_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len);
void too_short(struct timeval ts, const char *truncated_hdr);
const char *timestamp_string(timeval ts);

int main(int argv, char** argc) {

    //exit signal
    signal(SIGINT, exit_signal);

    r = i = w = p = b = c = s = d = false;

    if(!parseInput(argv, argc)){
        std::cout << "usage: ./balancer [-r filename] [-i interface] [ -l filename ] " <<
                        "[-p] [-b] [-s] [-d] \n or \n" <<
                        "./balancer [-r filename] [-i interface] " <<
                        "[-w num] [ -l filename ] [-c configpercent]" << std::endl;
        return 1;
    }

    if(i == true){

        /*interface = std::string(pcap_lookupdev(errBuff));
        if (interface == "") {
            fprintf(stderr, "Couldn't find default device: %s\n", errBuff);
            return(2);
        }*/

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

        //looping through every packet the sniff device gets
        //get_packet is the call back function
        while(true){
            packet = pcap_next(handle, &header);
            got_packet(&header, packet, pktIndex);
        }

    }else{// r == true
        std::cout << "in offline" << std::endl;
        if((handle = pcap_open_offline(filename.c_str(), errBuff)) == NULL){
            std::cerr << "Problem in funct pcap_open_offline: " << errBuff << std::endl << strerror(errno) << std::endl;
            return 1;
        }

        while((packet = pcap_next(handle, &header))){
            got_packet(&header, packet, pktIndex);
        }
    }

    //calling exit signal
    exit_signal(0);

    return 0;
}

void got_packet(const pcap_pkthdr *header, const u_char *packet, int & pktIndex){

    const sniff_ethernet *ethernet; /* The ethernet header */
    const sniff_ip *ip_; /* The IP header */
    const sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    if(packet == NULL){
        std::cout << "returning" << std::endl;
        return;
    }
    ++pktIndex;//increase packet count if it is valid

    //casting the packet
    ethernet = (sniff_ethernet*)packet;
    ip_ = (sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip_)*4;
    if (size_ip < 20) {
        //std::cerr << "Problem in funct get_packet, out in size_ip. \n invalid size_ip.";
        return;
    }

    if (ip_->ip_p == IPPROTO_UDP){

        ip *ip_udp;
        UDP_hdr *udp;
        unsigned int IP_header_length;
        int capture_len = header->caplen;
        timeval ts = header->ts;

        /* For simplicity, we assume Ethernet encapsulation. */

        if (capture_len < sizeof(ether_header)){
            /* We didn't even capture a full Ethernet header, so we
             * can't analyze this any further.
             */
            too_short(ts, "Ethernet header");
            return;
        }

        /* Skip over the Ethernet header. */
        packet += sizeof(ether_header);
        capture_len -= sizeof(ether_header);

        if (capture_len < sizeof(ip_udp)){ /* Didn't capture a full IP header */
            too_short(ts, "IP header");
            return;
        }

        ip_udp = (ip*) packet;
        IP_header_length = ip_udp->ip_hl * 4;   /* ip_hl is in 4-byte words */

        if (capture_len < IP_header_length)
            { /* didn't capture the full IP header including options */
            too_short(ts, "IP header with options");
            return;
            }

        /* Skip over the IP header to get to the UDP header. */
        packet += IP_header_length;
        capture_len -= IP_header_length;

        if (capture_len < sizeof(UDP_hdr))
            {
            too_short(ts, "UDP header");
            return;
            }

        udp = (UDP_hdr*) packet;

        printf("%s UDP src_port=%d dst_port=%d length=%d\n",
            timestamp_string(ts),
            ntohs(udp->uh_sport),
            ntohs(udp->uh_dport),
            ntohs(udp->uh_ulen));


        std::string keyString;
        if(s && d){
            keyString = std::string(inet_ntoa(ip_->ip_src)) + SEPARATOR + std::string(inet_ntoa(ip_->ip_dst));
        }else if(s){
            keyString = inet_ntoa(ip_->ip_src);
        }else{// !d
            keyString = inet_ntoa(ip_->ip_dst);
        }

        //adding it to database/table
        std::unordered_map<std::string, int >::iterator it;
        it = db_packetCount.find(keyString);

        int HeadersSum =  size_ip + ntohs(udp->uh_ulen) + ntohs(ip_->ip_len) - (size_ip + ntohs(udp->uh_ulen));// + payload;

        if(it == db_packetCount.end()){//new element
            db_packetCount.insert(make_pair(keyString, 1));
            db_bytesCount.insert(make_pair(keyString, HeadersSum));
        }else{
            ++it->second;
            it = db_bytesCount.find(keyString);
            it->second += HeadersSum;
        }

        std::cout << "Packet #:  " << pktIndex << std::endl;
        std::cout << "Protocol:  " << "UDP" << std::endl;
        std::cout << "From:      " << inet_ntoa(ip_->ip_src) << std::endl;
        std::cout << "To:        " << inet_ntoa(ip_->ip_dst) << std::endl;
        std::cout << "Size:      " << HeadersSum << std:: endl << std::endl;

    }else if(ip_->ip_p == IPPROTO_TCP){

        tcp = (sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            //std::cerr << "Problem in funct get_packet, out in size_tcp. \n invalid size_tcp.";
            return;
        }
        payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);


        std::string keyString;
        if(s && d){
            keyString = std::string(inet_ntoa(ip_->ip_src)) + SEPARATOR + std::string(inet_ntoa(ip_->ip_dst));
        }else if(s){
            keyString = inet_ntoa(ip_->ip_src);
        }else{// !d
            keyString = inet_ntoa(ip_->ip_dst);
        }

        //adding it to database/table
        std::unordered_map<std::string, int >::iterator it;
        it = db_packetCount.find(keyString);

        int HeadersSum =  size_ip + size_tcp + ntohs(ip_->ip_len) - (size_ip + size_tcp);;// + payload;

        if(it == db_packetCount.end()){//new element
            db_packetCount.insert(make_pair(keyString, 1));
            db_bytesCount.insert(make_pair(keyString, HeadersSum));
        }else{
            ++it->second;
            it = db_bytesCount.find(keyString);
            it->second += HeadersSum;
        }

        std::cout << "Packet #:  " << pktIndex << std::endl;
        std::cout << "Protocol:  " << "TCP" << std::endl;
        std::cout << "From:      " << inet_ntoa(ip_->ip_src) << std::endl;
        std::cout << "To:        " << inet_ntoa(ip_->ip_dst) << std::endl;
        std::cout << "Size:      " << HeadersSum << std:: endl << std::endl;

    }else{
        std::cout << "Not a UDP ot TCP packet, returning" << std::endl;
        return;
    }

}

void printParsedResults(){
    std::cout << "filename      =  " << filename << std::endl;
    std::cout << "-r            =  " << r << std::endl;
    std::cout << "interface     =  " << interface << std::endl;
    std::cout << "-i            =  " << i << std::endl;
    std::cout << "w             =  " << w << std::endl;
    std::cout << "num           =  " << num << std::endl;
    std::cout << "logfile       =  " << logfile << std::endl;
    std::cout << "configpercent =  " << configpercent << std::endl;
    std::cout << "p             =  " << p << std::endl;
    std::cout << "b             =  " << b << std::endl;
    std::cout << "s             =  " << s << std::endl;
    std::cout << "d             =  " << d << std::endl;
}

void too_short(struct timeval ts, const char *truncated_hdr){
    fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
        timestamp_string(ts), truncated_hdr);
}

const char *timestamp_string(timeval ts){
    static char timestamp_string_buf[256];

    sprintf(timestamp_string_buf, "%d.%06d",
        (int) ts.tv_sec, (int) ts.tv_usec);

    return timestamp_string_buf;
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
    for(int i_ = 1; i_ < argv; ++i_){
        #if DEBUGPARSE
            std::cout << "argc[" << i_ << "]: " << argc[i_] << std:: endl;
            std::cout << "-r " << strcmp(argc[i], "-r") << std::endl;
            std::cout << "-i " << strcmp(argc[i], "-i") << std::endl;
            std::cout << "-w " << strcmp(argc[i], "-w") << std::endl;
            std::cout << "-l " << strcmp(argc[i], "-l") << std::endl;
            std::cout << "-c " << strcmp(argc[i], "-c") << std::endl;
            std::cout << "-p " << strcmp(argc[i], "-p") << std::endl;
            std::cout << "-b " << strcmp(argc[i], "-b") << std::endl;
            std::cout << "-s " << strcmp(argc[i], "-s") << std::endl;
            std::cout << "-d " << strcmp(argc[i], "-d") << std::endl;
        #endif
        if(strcmp(argc[i_], "-r") == 0){
            r = true;
            filename = std::string(argc[++i_]);
            #if DEBUGPARSE
                std::cout << "filename " << filename << std:: endl;
            #endif
        }else if(strcmp(argc[i_], "-i") == 0){
            i = true;
            interface = std::string(argc[++i_]);
            #if DEBUGPARSE
                std::cout << "interface " << interface << std:: endl;
            #endif
        }else if(strcmp(argc[i_], "-w") == 0){
            w = true;
            std::stringstream ss;
            ss << argc[++i_];
            ss >> num;
            #if DEBUGPARSE
                std::cout << "num " << num << std:: endl;
            #endif
        }else if(strcmp(argc[i_], "-l") == 0){
            logfile = std::string(argc[++i_]);
            #if DEBUGPARSE
                std::cout << "logfile " << logfile << std:: endl;
            #endif
        }else if(strcmp(argc[i_], "-c") == 0){
            c = true;
            configpercent = std::string(argc[++i_]);
            #if DEBUGPARSE
                std::cout << "configpercent " << configpercent << std:: endl;
            #endif
        }else if(strcmp(argc[i_], "-s") == 0){
            s = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-s = true: " << std:: endl;
            #endif
        }else if (strcmp(argc[i_], "-d") == 0){
            d = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-d = true" << argc[i_] << std:: endl;
            #endif
        }else if(strcmp(argc[i_], "-p") == 0){
            p = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-p = true" << argc[i_] << std:: endl;
            #endif
        }else if(strcmp(argc[i_], "-b") == 0){
            b = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-b = true" << argc[i_] << std:: endl;
            #endif
        }else{
            std::cout << "unknown command: " << argc[i_] << std::endl;
            return false;
        }
    }

    balancer = (w && c) && (r != i) && (!p && !b && !s && !d);
    sniffer  = (p || b) && (s || d) && (!w);

    //at least two flag and at least -s || -d have to be true
    if(balancer == sniffer) {
        return false;
    }

    #if DEBUGPARSE
        printParsedResults();
    #endif

    return true;
}

/*io manipulator function to print table in well formated order. Taken from:
http://stackoverflow.com/questions/14765155/how-can-i-easily-format-my-data-table-in-c */
template<typename T> void printE(std::ofstream & ofile, T t, const int& width)
{
    char fill = ' ';
    ofile << std::left << std::setw(width) << std::setfill(fill) << t;
}

void exit_signal(int signal){
    std::ofstream ofile(logfile);

    int sW, dW, pW, bW;

    sW = dW = 18;
    pW = 12;
    bW = 12;

    //writing out first rows
    if(s){
        printE(ofile, SRC, sW);
    }
    if(d){
        printE(ofile, DST, dW);
    }
    if(p){
        printE(ofile, PACKET, pW);
    }
    if(b){
        printE(ofile, BYTES, bW);
    }
    ofile << std::endl;

    //writing rest of the rows
    std::unordered_map<std::string, int>::iterator it, it2;
    for(it = db_packetCount.begin(); it != db_bytesCount.end(); ++it){
        if(s && d){
            std::string source, destination;
            std::stringstream ss;
            ss << it->first;
            ss >> source >> destination;

            #if DBO
                std::cout << "if(s && d){...}" << std::endl;
                std::cout << "it->first: " << it->first << std::endl;
                std::cout << "Source: " << source << std::endl;
                std::cout << "Destination: " << destination << std::endl;
            #endif

            //printing to database
            printE(ofile, source, sW);
            printE(ofile, destination, dW);

        }else{
            printE(ofile, it->first, dW);
        }

        if(p){
            printE(ofile, it->second, pW);
        }
        if(b){
            it2 = db_bytesCount.find(it->first);
            printE(ofile, it2->second, dW);
        }

        ofile << std::endl;
    }

    ofile.close();

    std::cout << "Exited with signal: " << signal << std::endl;

    //closing sniffing in interface
    if(i){
        pcap_freecode(&fp);
        pcap_close(handle);
    }
    exit(signal);
}











