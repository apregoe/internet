#include "sniff.h"// taken from http://www.tcpdump.org/pcap.html

#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <string>

#include <unordered_map>
#include <vector>

#include <pcap.h>

#include <arpa/inet.h>

//compile-time definitions
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define MAX_COLUMNS 4
#define SEPARATOR " "

//Global variables
/*
sudo ./balancer -i en0 -l logfile.txt -s -d -p -b
*/
//user input
std::string filename, logfile, interface, num, configpercent;
bool r, i, w, p, b, s, d;//flags

//database
//table
std::unordered_map<std::string, int > db_bytesCount;
std::unordered_map<std::string, int > db_packetCount;
std::string firstRow[4];
//database constants
const std::string PACKET = "Packets";
const std::string BYTES  = "Bytes";
const std::string SRC    = "Source";
const std::string DST    = "Destination";


//func signatures
bool parseInput(int argv, char** argc);//parses input
void printParsedResults();//prints results
void got_packet(const pcap_pkthdr *header, const u_char *packet, int & pktCount);
void exit_signal(int signal);//function called when Ctr+C

int main(int argv, char** argc) {

    //exit signal
    signal(SIGINT, exit_signal);

    r = i = p = b = s = d = false;
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    bpf_program fp;//compiled version of our filter
    bpf_u_int32 mask;//The netmask of our sniffing device
    bpf_u_int32 net;//The IP of our sniffing device
    pcap_pkthdr header;//header of the received packet
    const u_char* packet = NULL;//packet received
    int pktCount = 0;//packet number that is being sniffed

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

    if(r){
        //opening pcap in which we will sniff
        if((handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errBuff)) == NULL){
            std::cerr << "Problem in funct pcap_open_live: " << errBuff << std::endl << strerror(errno) << std::endl;
            return 1;
        }
    }else{
        if((handle = pcap_open_live(filename.c_str(), errBuff)) == NULL){
            std::cerr << "Problem in funct pcap_open_live: " << errBuff << std::endl << strerror(errno) << std::endl;
            return 1;
        }
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
        got_packet(&header, packet, pktCount);
    }
    pcap_close(handle);

    return 0;
}

void got_packet(const pcap_pkthdr *header, const u_char *packet, int & pktCount){

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
    ++pktCount;//increase packet count if it is valid

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


    std::string keyString;
    if(s && d){
        keyString = std::string(inet_ntoa(ip->ip_src)) + SEPARATOR + std::string(inet_ntoa(ip->ip_dst));
    }else if(s){
        keyString = inet_ntoa(ip->ip_src);
    }else{// !d
        keyString = inet_ntoa(ip->ip_dst);
    }

    //adding it to database/table
    std::unordered_map<std::string, int >::iterator it;
    it = db_packetCount.find(keyString);

    if(it == db_packetCount.end()){//new element
        db_packetCount.insert(make_pair(keyString, 1));
        db_bytesCount.insert(make_pair(keyString, header->len));
    }else{
        ++it->second;
        it = db_bytesCount.find(keyString);
        it->second += header->len;
    }

    std::cout << "Packet #:  " << pktCount << std::endl;
    std::cout << "From:      " << inet_ntoa(ip->ip_src) << std::endl;
    std::cout << "To:        " << inet_ntoa(ip->ip_dst) << std::endl;
    std::cout << "Size:      " << header->len << std:: endl << std::endl;

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
            std::cout << "-w " << strcmp(argc[i], "-w") << std::endl;
            std::cout << "-l " << strcmp(argc[i], "-l") << std::endl;
            std::cout << "-c " << strcmp(argc[i], "-c") << std::endl;
            std::cout << "-p " << strcmp(argc[i], "-p") << std::endl;
            std::cout << "-b " << strcmp(argc[i], "-b") << std::endl;
            std::cout << "-s " << strcmp(argc[i], "-s") << std::endl;
            std::cout << "-d " << strcmp(argc[i], "-d") << std::endl;
        #endif
        if(strcmp(argc[i], "-r") == 0){
            r = true;
            filename = std::string(argc[++i]);
            #if DEBUGPARSE
                std::cout << "filename " << filename << std:: endl;
            #endif
        }else if(strcmp(argc[i], "-i") == 0){
            i = true;
            interface = std::string(argc[++i]);
            #if DEBUGPARSE
                std::cout << "interface " << interface << std:: endl;
            #endif
        }else if(strcmp(argc[i], "-w") == 0){
            num = std::string(argc[++i]);
            w = true;
            #if DEBUGPARSE
                std::cout << "num " << num << std:: endl;
            #endif
        }else if(strcmp(argc[i], "-l") == 0){
            logfile = std::string(argc[++i]);
            #if DEBUGPARSE
                std::cout << "logfile " << logfile << std:: endl;
            #endif
        }else if(strcmp(argc[i], "-c") == 0){
            configpercent = std::string(argc[++i]);
            #if DEBUGPARSE
                std::cout << "configpercent " << configpercent << std:: endl;
            #endif
        }else if(strcmp(argc[i], "-s") == 0){
            s = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-s = true: " << std:: endl;
            #endif
        }else if (strcmp(argc[i], "-d") == 0){
            d = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-d = true" << argc[i] << std:: endl;
            #endif
        }else if(strcmp(argc[i], "-p") == 0){
            p = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-p = true" << argc[i] << std:: endl;
            #endif
        }else if(strcmp(argc[i], "-b") == 0){
            b = true;
            ++flagsCount;
            #if DEBUGPARSE
                std::cout << "-b = true" << argc[i] << std:: endl;
            #endif
        }else{
            std::cout << "unknown command: " << argc[i] << std::endl;
            return false;
        }
    }



    //at least two flag and at least -s || -d have to be true
    /*if(!(flagsCount > 1) || ((!s && !d) || (!p && !b)) ){
        return false;
    }*/

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
    exit(signal);
}


void printParsedResults(){
    std::cout << "filename      =  " << filename << std::endl;
    std::cout << "interface     =  " << interface << std::endl;
    std::cout << "num           =  " << num << std::endl;
    std::cout << "logfile       =  " << logfile << std::endl;
    std::cout << "configpercent =  " << configpercent << std::endl;
    std::cout << "p             =  " << p << std::endl;
    std::cout << "b             =  " << b << std::endl;
    std::cout << "s             =  " << s << std::endl;
    std::cout << "d             =  " << d << std::endl;
}











