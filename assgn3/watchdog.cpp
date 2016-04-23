#define _GLIBCXX_USE_NANOSLEEP 1

#include "sniff.h"//ip headers struct

#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <csignal>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cmath>
#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <sstream>

#include <iomanip>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <map>
#include <pcap.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>


#define MAXDATASIZE 1024
#define SIZE_ETHERNET 14



    //variables declaration

    //sniffing variables. I made them global since I use most of them in different functions
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    bpf_program fp;//compiled version of our filter
    bpf_u_int32 mask;//The netmask of our sniffing device
    bpf_u_int32 net;//The IP of our sniffing device
    pcap_pkthdr header;//header of the received packet
    int pktIndex = 0;
    int currSec = 0;
    int prevSec = 0;


    //local parsing data
    std::ofstream logfile;
    std::ofstream imageFILE;
    std::string interface, writeFileName, readFileName;
    bool iFlag = false;


    //client (local/me) data
    addrinfo hints, *allInfo;
    int localSocket = 0;
    std::string sendBuf;
    char recvBuf[MAXDATASIZE];
    int realNumberBytes;
    const char* myIP;
    std::string myID;
    const u_char* packet = NULL;//packet received

    //server (remote) data
    std::string desmanIP;
    std::string port = "11353";
    char hostname[MAXDATASIZE], hostservice[20];

    //database, it is wiped every second
    int reportNumber = 0;
    std::unordered_set<std::string> flowSet;
    std::unordered_map<std::string,int> ipCountTable;
    long int pktCount = 0;
    long int prevPktCount = 0;
    long int prevByteCount = 0;
    unsigned int prevFlowCount = 0;
    long int byteCount = 0;//ip_size + tcp/udp_size + payload;
    long long int maxIPCount = 0;
    std::string maxIP;

    std::mutex theLock;




void exit_signal(int signal);//function called when Ctr+C
void parseInput(char **argc, int argv);
void closeMe();
void got_packet(const pcap_pkthdr *header, const u_char *packet);
std::string getFlowString(std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string protocol);
void too_short(struct timeval ts, const char *truncated_hdr);
const char *timestamp_string(timeval ts);
template<typename T> void printE(std::ofstream & ofile, T t, const int& width);
//I got this function from Beej's Guide to Network Programming
void *get_in_addr(struct sockaddr *sa);

int main(int argv, char* argc[]){//client –u –s desmanIP –p portno –l logfile

//exit signal
    signal(SIGINT, exit_signal);

#if DEBUG
    for(int i = 0; i < argv; ++i){
        //std::cout << *(argc+i) << " " << std::endl;
    }
#endif

    if(argv < 7){
        std::cerr << "watchdog [-r filename] [-i interface] [ -w filename ] [-c desmanIP]"<< std::endl;
        return 1;
    }

    //parsing input
    parseInput(argc, argv);

#if DEBUG
    //std::cout << "info after parsing: " <<std::endl;
    //std::cout << "readFileName: " << readFileName << std::endl;
    //std::cout << "writeFileName: " << writeFileName << std::endl;
    //std::cout << "desmanIP: " << desmanIP << std::endl;
    //std::cout << "interface: " << interface << std::endl;
    //std::cout << "argv: " << argv << std::endl;
#endif

    //opening logfile
    logfile.open(writeFileName);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    //getting my ipv4 address
    ifaddrs * linkedlist;
    if(getifaddrs(&linkedlist) != 0){
        std::cerr << "" << std::endl;
    }
    while(linkedlist != NULL){

        char tempIP[INET6_ADDRSTRLEN];
        sockaddr* temp = linkedlist->ifa_addr;
        if(temp->sa_family == AF_INET){
            myIP = inet_ntop(AF_INET, get_in_addr((struct sockaddr *)temp), tempIP, sizeof tempIP);
            char tempip[INET_ADDRSTRLEN];
            strcpy(tempip,myIP);
            tempip[6] = '\0';
            if((strcmp(myIP+2, "0.0.0.0") != 0) && (strcmp(tempip, "127.0.") != 0)){
                break;
            }
        }
        linkedlist = linkedlist->ifa_next;
    }


    logfile << "Conencting to desman at " + desmanIP << "..." << std::endl;
    //std::cout << "Conencting to desman at " + desmanIP << "..." << std::endl;

    if(getaddrinfo(desmanIP.c_str(), port.c_str(), &hints, &allInfo) < 0){
        std::cerr << "Problem getting address info:" << std::endl << strerror(errno) << std::endl;
        logfile.close();
        return 1;
    }

    //getting the rest of the connection set up

    while(allInfo != NULL){
        if ((localSocket = socket(allInfo->ai_family, allInfo->ai_socktype,
                             allInfo->ai_protocol)) == -1) {
            perror("watchdog: socket");
            allInfo = allInfo->ai_next;
            continue;
        }
        if (connect(localSocket, allInfo->ai_addr, allInfo->ai_addrlen) == -1) {
            close(localSocket);
            perror("watchdog: connect");
            allInfo = allInfo->ai_next;
            continue;
        }
        break;
    }


    //getting names from the host
    getnameinfo(allInfo->ai_addr, allInfo->ai_addrlen, hostname, sizeof hostname, hostservice, sizeof hostservice, 0);

    //message interaction started
    //receiving my designated ID
    if((realNumberBytes = recv(localSocket, recvBuf, MAXDATASIZE-1,0)) < 0){
        std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
        logfile.close();
        return 1;
    }
    recvBuf[realNumberBytes] = '\0';

    //parsing the message that contains: my wathcdog ID (myID)
    std::stringstream sss;
    std::string unused;
    sss << recvBuf;
    sss >> unused;
    sss >> myID;
    logfile << "Received " << myID << std::endl;
    //std::cout << "Received " << myID << std::endl;


    //waiting for the start signal
    if((realNumberBytes = recv(localSocket, recvBuf, MAXDATASIZE-1,0)) < 0){
        std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
        logfile.close();
        return 1;
    }
    recvBuf[realNumberBytes] = '\0';
    //std::cout << "recvBuf = " << recvBuf << std::endl;
    if(strcmp(recvBuf, "start") != 0){
        //std::cout << "Terminating watchdog" << std::endl;
        logfile.close();
        return 0;
    }
    logfile << "Received start..." << std::endl;
    //std::cout << "Received start..." << std::endl;


    //starting to sniff
    if(iFlag == true){

        /*interface = std::string(pcap_lookupdev(errBuff));
        if (interface == "") {
            fprintf(stderr, "Couldn't find default device: %s\n", errBuff);
            return(2);
        }*/

        //getting network from mask and interface
        if(pcap_lookupnet(interface.c_str(), &net, &mask, errBuff) == -1){
            std::cerr << "Problem in funct pcap_lookupnet: " << errBuff << std::endl;
            return 1;
        }

        //opening pcap in which we will sniff
        if((handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errBuff)) == NULL){
            std::cerr << "Problem in funct pcap_open_live: " << errBuff << std::endl;
            return 1;
        }

        //verifying correct data link
        if(pcap_datalink(handle) != DLT_EN10MB){
            std::cerr << "Problem in funct pcap_datalink: " << errBuff << std::endl;
            return 1;
        }

        //compile version
        if(pcap_compile(handle, &fp, "ip", 0, net) == -1){
            std::cerr << "Problem in funct pcap_compile: " << errBuff << std::endl;
            return 1;
        }

        //looping through every packet the sniff device gets
        //get_packet is the call back function
        while(true){
            packet = pcap_next(handle, &header);
            theLock.lock();//making it atomic!
            got_packet(&header, packet);
            theLock.unlock();

            theLock.lock();
            if(currSec != prevSec){
                reportNumber++;
                
                //std::cout << currSec << " " << prevSec << "  " << reportNumber << std::endl;

                std::stringstream ss;
                std::string reportNumberS, pktCountS, byteCountS, flowCountS;
                ss << reportNumber;
                ss >> reportNumberS;
                ss.clear();
                ss << pktCount;
                ss >> pktCountS;
                ss.clear();
                ss << byteCount;
                ss >> byteCountS;
                ss.clear();
                ss << flowSet.size();
                ss >> flowCountS;
                ss.clear();


                //bool for 0 pkts consecutive
                bool flag = pktCount == 0 && byteCount == 0 && flowSet.size() == 0 && prevFlowCount == 0 && prevPktCount == pktCount && prevByteCount == byteCount;
                if(((prevPktCount*3 > pktCount) && (prevByteCount*3 > byteCount) && (prevFlowCount*3 > flowSet.size())) || (flag)){
                    sendBuf = "report                    " + reportNumberS + "    " + pktCountS + "    " + byteCountS + "    " + flowCountS;
                    if(send(localSocket, sendBuf.c_str(), sendBuf.length(), 0) < 0){
                        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        closeMe();
                        theLock.unlock();
                        return 0;
                    }
                    std::this_thread::sleep_for (std::chrono::milliseconds(200));

                    std::cout << "report   " << reportNumber << " " << pktCount << " " << byteCount << " " << flowSet.size() << std::endl;

                    //adding it to the writefile
                    logfile << sendBuf << std::endl;
                }else{
                    std::cout << "alert type";
                    logfile << "alert type";
                    if(prevPktCount*3 <= pktCount){
                        std::cout << " packets";
                        logfile << " packets";
                    }if(prevByteCount*3 <= byteCount){
                        std::cout << " bytes";
                        logfile << " bytes";
                    }if(prevFlowCount*3 <= flowSet.size()){
                        std::cout << " flows";
                        logfile << " flows";
                    }
                    std::cout << std::endl;
                    logfile << std::endl;

                    sendBuf = "alert report              " + reportNumberS + "    " + pktCountS + "    " + byteCountS + "    " + flowCountS + "    " + maxIP;
                    if(send(localSocket, sendBuf.c_str(), sendBuf.length(), 0) < 0){
                        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        closeMe();
                        theLock.unlock();
                        return 0;
                    }

                    std::this_thread::sleep_for (std::chrono::milliseconds(200));
                    std::cout << sendBuf << std::endl;
                    logfile << sendBuf << std::endl;
                }

                //refreshing the counters to 0! new log
                prevByteCount = byteCount;
                prevPktCount = pktCount;
                prevFlowCount = flowSet.size();
                pktCount = byteCount = 0;
                maxIPCount = 0;
                maxIP = "";
                flowSet.clear();

            }
            theLock.unlock();
        }

    }else{// r == true
        if((handle = pcap_open_offline(readFileName.c_str(), errBuff)) == NULL){
            std::cerr << "Problem in funct pcap_open_offline: " << errBuff << std::endl;
            return 1;
        }

        while((packet = pcap_next(handle, &header))){
            theLock.lock();
            got_packet(&header, packet);
            theLock.unlock();

            theLock.lock();
            if(currSec != prevSec){
                reportNumber++;
                
                //std::cout << currSec << " " << prevSec << "  " << reportNumber << std::endl;

                std::stringstream ss;
                std::string reportNumberS, pktCountS, byteCountS, flowCountS;
                ss << reportNumber;
                ss >> reportNumberS;
                ss.clear();
                ss << pktCount;
                ss >> pktCountS;
                ss.clear();
                ss << byteCount;
                ss >> byteCountS;
                ss.clear();
                ss << flowSet.size();
                ss >> flowCountS;
                ss.clear();


                //bool for 0 pkts consecutive
                bool flag = pktCount == 0 && byteCount == 0 && flowSet.size() == 0 && prevFlowCount == 0 && prevPktCount == pktCount && prevByteCount == byteCount;
                if(((prevPktCount*3 > pktCount) && (prevByteCount*3 > byteCount) && (prevFlowCount*3 > flowSet.size())) || (flag)){
                    sendBuf = "report                    " + reportNumberS + "    " + pktCountS + "    " + byteCountS + "    " + flowCountS;
                    if(send(localSocket, sendBuf.c_str(), sendBuf.length(), 0) < 0){
                        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        closeMe();
                        theLock.unlock();
                        return 0;
                    }
                    std::this_thread::sleep_for (std::chrono::milliseconds(200));

                    std::cout << "report   " << reportNumber << " " << pktCount << " " << byteCount << " " << flowSet.size() << std::endl;

                    //adding it to the writefile
                    logfile << sendBuf << std::endl;
                }else{
                    std::cout << "alert type";
                    logfile << "alert type";
                    if(prevPktCount*3 <= pktCount){
                        std::cout << " packets";
                        logfile << " packets";
                    }if(prevByteCount*3 <= byteCount){
                        std::cout << " bytes";
                        logfile << " bytes";
                    }if(prevFlowCount*3 <= flowSet.size()){
                        std::cout << " flows";
                        logfile << " flows";
                    }
                    std::cout << std::endl;
                    logfile << std::endl;

                    sendBuf = "alert report              " + reportNumberS + "    " + pktCountS + "    " + byteCountS + "    " + flowCountS + "    " + maxIP;
                    if(send(localSocket, sendBuf.c_str(), sendBuf.length(), 0) < 0){
                        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        closeMe();
                        theLock.unlock();
                        return 0;
                    }

                    std::this_thread::sleep_for (std::chrono::milliseconds(200));
                    std::cout << sendBuf << std::endl;
                    logfile << sendBuf << std::endl;
                }

                //refreshing the counters to 0! new log
                prevByteCount = byteCount;
                prevPktCount = pktCount;
                prevFlowCount = flowSet.size();
                pktCount = byteCount = 0;
                maxIPCount = 0;
                maxIP = "";
                flowSet.clear();

            }
            theLock.unlock();
        }
    }
    logfile.close();
    closeMe();
    return 0;
}


void got_packet(const pcap_pkthdr *header, const u_char *packet){

    const sniff_ethernet *ethernet; /* The ethernet header */
    const sniff_ip *ip_; /* The IP header */
    const sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */
    timeval ts = header->ts;/*timestamp*/

    prevSec = currSec;
    currSec = (int) ts.tv_sec;

    //UDP protocol variables
    ip *ip_udp;
    UDP_hdr *udp;
    unsigned int IP_header_length;
    unsigned int capture_len = header->caplen;

    std::string currentFlowString;//It's the current flow (src + " " + dst + " " + PortS ...)
    std::string dstIP;

    u_int size_ip;
    u_int size_tcp;

    if(packet == NULL){
        //std::cout << "returning" << std::endl;
        return;
    }

    //casting the packet
    ethernet = (sniff_ethernet*)packet;
    ip_ = (sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip_)*4;
    if (size_ip < 20) {
        //std::cerr << "Problem in funct get_packet, out in size_ip. \n invalid size_ip.";
        return;
    }

    if (ip_->ip_p == IPPROTO_UDP){//UDP protocol (identifier == 17)

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

        if (capture_len < IP_header_length){ /* didn't capture the full IP header including options */
            too_short(ts, "IP header with options");
            return;
        }

        /* Skip over the IP header to get to the UDP header. */
        packet += IP_header_length;
        capture_len -= IP_header_length;

        if (capture_len < sizeof(UDP_hdr)){
            too_short(ts, "UDP header");
            return;
        }

        //increase packet count if it is valid
        //I do it here because it's when the pkt is 100% valid to read
        ++pktCount;

        //updating the bytecount
        udp = (UDP_hdr*) packet;
        byteCount +=  size_ip + ntohs(udp->uh_ulen) + ntohs(ip_->ip_len) - (size_ip + ntohs(udp->uh_ulen));// + payload;


        //getting flow and dstIP
        currentFlowString =  getFlowString(inet_ntoa(ip_->ip_src), inet_ntoa(ip_->ip_dst), 
                                            (int)ntohs(udp->uh_sport), (int)ntohs(udp->uh_dport), "UDP"); 
        dstIP = inet_ntoa(ip_->ip_dst);

        //database manipulation
        //adding flow to it's table
        flowSet.insert(currentFlowString);
        //updating ip_Count table
        std::unordered_map<std::string, int>::iterator ipIt = ipCountTable.find(dstIP);
        if(ipIt == ipCountTable.end()){
            ipCountTable.insert(std::make_pair(dstIP,1));

            if(maxIPCount <= 1){
                maxIPCount = 1;
                maxIP = dstIP;
            }
        }else{
            ipIt->second += 1;
            if(maxIPCount <= ipIt->second){
                maxIPCount = ipIt->second;
                maxIP = ipIt->first;
            }
        }
    }else if(ip_->ip_p == IPPROTO_TCP){//TCP protocol (I think is 6)

        tcp = (sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            //std::cerr << "Problem in funct get_packet, out in size_tcp. \n invalid size_tcp.";
            return;
        }

        //increase packet count if it is valid
        //I do it here because it's when the pkt is 100% valid to read
        ++pktCount;

        payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        byteCount =  size_ip + size_tcp + ntohs(ip_->ip_len) - (size_ip + size_tcp);// + payload;

        //if balancer mode
            //printf("TCP src_port=%d dst_port=%d\n",
                //timestamp_string(ts),
              //  ntohs(tcp->th_sport),
               // ntohs(tcp->th_dport));
        currentFlowString =  getFlowString(inet_ntoa(ip_->ip_src), inet_ntoa(ip_->ip_dst), 
                                            (int)ntohs(tcp->th_sport), (int)ntohs(tcp->th_dport), "TCP"); 
        dstIP = inet_ntoa(ip_->ip_dst);

        //database manipulation
        //adding flow to it's table
        flowSet.insert(currentFlowString);
        //updating ip_Count table
        std::unordered_map<std::string, int>::iterator ipIt = ipCountTable.find(dstIP);
        if(ipIt == ipCountTable.end()){
            ipCountTable.insert(std::make_pair(dstIP,1));

            if(maxIPCount <= 1){
                maxIPCount = 1;
                maxIP = dstIP;
            }
        }else{
            ipIt->second += 1;
            if(maxIPCount <= ipIt->second){
                maxIPCount = ipIt->second;
                maxIP = ipIt->first;
            }
        }
    }else{
        ////std::cout << "Not a UDP or TCP packet, returning" << std::endl;
        return;
    }
}

std::string getFlowString(std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string protocol){
    std::string p1, p2;
    std::stringstream ss;
    ss << srcPort;
    ss >> p1;
    ss.clear();
    ss << dstPort;
    ss >> p2;
    return std::string(srcIP + " " + dstIP + " " + p1 + " " + p2 + " " + protocol);
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


void *get_in_addr(struct sockaddr *sa){
    if (sa->sa_family == AF_INET) {
    #if DEBUGIP
        //std::cout << "ipv4" << std::endl;
    #endif
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    #if DEBUGIP
    //std::cout << "ipv6" << std::endl;
    #endif
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void parseInput(char **argc, int argv) {
    #if DEBUGPARSE
        //std::cout << "inside parseInput()" << std::endl;
    #endif
        for(int i = 0; i < argv; ++i){
    #if DEBUGPARSE
            //std::cout << "argc[" << i << "]: " << argc[i] << std::endl;
            //std::cout << "-r" << strcmp(argc[i], "-r") << std::endl;
            //std::cout << "-i" << strcmp(argc[i], "-i") << std::endl;
            //std::cout << "-w" << strcmp(argc[i], "-w") << std::endl;
            //std::cout << "-c" << strcmp(argc[i], "-c") << std::endl;
    #endif
            if(strcmp(argc[i], "-w") == 0){
                writeFileName = argc[++i];
    #if DEBUGPARSE
                //std::cout << "inside argc[" << i << "]: " << argc[i] << std:: endl;
    #endif
            }else if(strcmp(argc[i], "-i") == 0){
                interface = argc[++i];
                iFlag = true;
    #if DEBUGPARSE
                //std::cout << "inside argc[" << i << "]: " << argc[i] << std:: endl;
    #endif
            }else if(strcmp(argc[i], "-c") == 0){
                desmanIP = argc[++i];
    #if DEBUGPARSE
                //std::cout << "inside argc[" << i << "]: " << argc[i] << std:: endl;
    #endif
            }else if(strcmp(argc[i], "-r") == 0){
                readFileName = argc[++i];
                iFlag = false;
    #if DEBUGPARSE
                //std::cout << "inside argc[" << i << "]: " << argc[i] << std:: endl;
    #endif
            }
        }
}

/*io manipulator function to print table in well formated order. Taken from:
http://stackoverflow.com/questions/14765155/how-can-i-easily-format-my-data-table-in-c */
template<typename T> void printE(std::ofstream & ofile_, T t, const int& width){
    char fill = ' ';
    ofile_ << std::left << std::setw(width) << std::setfill(fill) << t;
}

void exit_signal(int signal){

    //telling the desman to close me!
    closeMe();

    //closing sniffing in interface
    if(iFlag){
        pcap_freecode(&fp);
    }
    pcap_close(handle);

    //closing the log file
    logfile.close();

    //std::cout << "Exited with signal: " << signal << std::endl;

    std::exit(signal);
    return;

}

void closeMe(){
    sendBuf = "close";
    if(send(localSocket, sendBuf.c_str(), sendBuf.length(), 0) < 0){
        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
        logfile.close();
        return;
    }
}






