#define _GLIBCXX_USE_NANOSLEEP 1

//thread manipulation and synch
#include <thread>
#include <mutex>          // std::mutex, std::lock
#include <chrono>

//standard and common libraries
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <cmath>
#include <iostream>
#include <fstream>
#include <signal.h>
#include <sstream>
//network libraries
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
//data structures
#include <unordered_map>
#include <vector>

/*The main structure of this file was taken from Beej's Guide to Network Programming
 * Nonetheless, it is not the same. I used Beej's Guide to Network Programming as a
 * guide*/



#define MAXDATASIZE 1024
#define PORT 11353
#define START_SIGNAL "s"


//global variables
typedef std::unordered_map<int,int> hashmap;
std::ofstream logfile;
std::mutex theLock;
char recvBuf[MAXDATASIZE];
hashmap clientTable;
long int totalPkts  = 0;
long int totalFlows = 0;
long int totalBytes = 0;


//I got this function from Beej's Guide to Network Programming
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
#if DEBUGIP
        std::cout << "ipv4" << std::endl;
#endif
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
#if DEBUGIP
    std::cout << "ipv6" << std::endl;
#endif
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//function called when Ctr+C
void exit_signal(int signal){
    logfile.close();
    exit(0);
}

void parseInput(std::string &writeFileName, int &watchdogsNums, int argv, char **argc);

void watchdog(int watchdogID, int clientSocket);
void processPkt(int watchdogID, int clientSocket);

std::string randomString();

int main(int argv, char* argc[]) {

    //handler to be called when Ctr+C
    // Register signals
    signal(SIGINT, exit_signal);

#if DEBUGIP
    ifaddrs * linkedlist_;
    if(getifaddrs(&linkedlist_) != 0){
       std::cerr << "fuck" << std::endl;
    }
    while(linkedlist_ != NULL){

        char tempIP[INET6_ADDRSTRLEN];
        sockaddr* temp = linkedlist_->ifa_addr;

        std::cout << inet_ntop(AF_INET, get_in_addr((struct sockaddr *)temp), tempIP, sizeof tempIP) << std::endl;
        linkedlist_ = linkedlist_->ifa_next;
    }
#endif


    if(argv < 5){
        std::cerr << "desman [ -w filename ] [-n number]"<< std::endl;
        return 1;
    }

    //declaring variables
    //local parsing data
    std::string writeFileName;
    int watchdogsNums;

    //local network related data (local)
    addrinfo hints, *allInfo;
    int localSocket;
    const char* localIP;
    int backlog = 0;
    std::string port = "11353";
    std::string sendBuf;

    //client data (remote)
    addrinfo clientAddr;//when receiving, this address is going to be filled up;
 //   socklen_t clientSockLen;
    char watchdogIP[INET_ADDRSTRLEN];
    std::string watchdogIPString;
    int clientSocket;//used for new connections
    int ID = 0;
    int watchdogID = 0;

#if DEBUG
    for(int i = 0; i < argv; ++i){
        std::cout << *(argc+i) << " " << std::endl;
    }
#endif

    //parsing
    parseInput(writeFileName, watchdogsNums, argv, argc);
    backlog = 1000;

#if DEBUG
    std::cout << "info after parsing: " <<std::endl
    std::cout << "writeFileName: " << writeFileName << std::endl;
#endif
    logfile.open(writeFileName);

    //initializing hints (ipv4)
    memset(&hints, 0, (sizeof hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;


    //getting my ipv4 address
    ifaddrs * linkedlist;
    if(getifaddrs(&linkedlist) != 0){
        std::cerr << "" << std::endl;
    }
    while(linkedlist != NULL){

        char tempIP[INET6_ADDRSTRLEN];
        sockaddr* temp = linkedlist->ifa_addr;
        if(temp->sa_family == AF_INET){
            localIP = inet_ntop(AF_INET, get_in_addr((struct sockaddr *)temp), tempIP, sizeof tempIP);
            char tempip[INET_ADDRSTRLEN];
            strcpy(tempip,localIP);
            tempip[6] = '\0';
            if((strcmp(localIP+2, "0.0.0.0") != 0) && (strcmp(tempip, "127.0.") != 0)){
                break;
            }
        }
        linkedlist = linkedlist->ifa_next;
    }

    //getting the info from the hints, completing it's struct and putting it into allInfo.
    //allInfo might also have an ipv6 from localhost
    if(getaddrinfo(localIP, port.c_str(), &hints, &allInfo) < 0){
        std::cerr << "Problem getting local address info:" << std::endl << strerror(errno) << std::endl;
        logfile.close();
        return 1;
    }

    //getting the local socket file descriptor
    while(allInfo != NULL){
        if ((localSocket = socket(allInfo->ai_family, allInfo->ai_socktype, allInfo->ai_protocol)) == -1) {
            close(localSocket);
            perror("desman: socket");
            allInfo = allInfo->ai_next;
            continue;
        }

        if (bind(localSocket, allInfo->ai_addr, allInfo->ai_addrlen) == -1) {
            close(localSocket);
            perror("desman: bind");
            allInfo = allInfo->ai_next;
            continue;
        }
        break;
    }


    //Starting server
    if(listen(localSocket, backlog) == -1){
        std::cerr << "Problem listening:" << std::endl << strerror(errno) << std::endl;
        logfile.close();
        return 1;
    }
    logfile << "Listening on port " << PORT << "..." << std::endl;
    std::cout << "Listening on port " << PORT << "..." << std::endl;

    //accepting incoming watchdogs until ID==watchdogsNums
    while(watchdogsNums != ID){
        //setting the ID
        ID++;
        watchdogID = ID;

        //accepting new connection
        clientSocket = accept(localSocket, (struct sockaddr *)&clientAddr, &clientAddr.ai_addrlen);
        if (clientSocket == -1) {
            perror("accept");
            continue;
        }

        //inserting the client Socket and id into the clientTable
        clientTable.insert(std::make_pair(ID,clientSocket));

        //getting client ip
        inet_ntop(AF_INET,
                  get_in_addr((struct sockaddr *)&clientAddr),
                  watchdogIP, clientAddr.ai_addrlen);

        logfile << "Incoming watchdog connection from IP " << watchdogIP << std::endl;
        std::cout << "Incoming watchdog connection from IP " << watchdogIP << std::endl;

        //sending the ID
        std::stringstream ss1;
        std::string temp;
        sendBuf = "UID ";
        ss1 << watchdogID;
        ss1 >> temp;
        sendBuf += temp;
        if(send(clientSocket, sendBuf.c_str(), sendBuf.length(), 0) < 0) {
            std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        logfile << "Assigned " << watchdogID << " to watchdog IP " << watchdogIP << std::endl;
        std::cout << "Assigned " << watchdogID << " to watchdog IP " << watchdogIP << std::endl;

        //waiting to send it, sleepping this thread for at least 10 milliseconds, then scheduling back again
        std::this_thread::sleep_for (std::chrono::milliseconds(100));

    }
    close(localSocket); // don't need the listener anymore

    //All connections have been stablished
    logfile << "All watchdogs connected..." << std::endl;
    std::cout << "All watchdogs connected..." << std::endl;

    //start signal transmission to all watchdogs
    logfile << "Issuing start monitoring..." << std::endl;
    std::cout << "Issuing start monitoring..." << std::endl;
    for(hashmap::iterator it = clientTable.begin(); it != clientTable.end(); ++it){
 
        //sending the start signal
        sendBuf = "start";
        if(send(it->second, sendBuf.c_str(), sendBuf.length(), 0) < 0) {
            std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        //waiting to send it, sleepping this thread for at least 10 milliseconds, then scheduling back again
        std::this_thread::sleep_for (std::chrono::milliseconds(100));
    }

    //for every watchdog/client, generate a child process with it's own watchdogID and clientSocket
    while(true){
        theLock.lock();

        if(clientTable.size() == 0){
            theLock.unlock();
            break;
        }
        std::vector<std::thread*> watchdogs;
        for(hashmap::iterator it = clientTable.begin(); it != clientTable.end(); ++it){
            std::thread* watchdogThread = new std::thread(watchdog, it->first, it->second);
            watchdogs.push_back(watchdogThread);
        }
        theLock.unlock();

        for(unsigned int i = 0; i < watchdogs.size(); ++i){
            watchdogs[i]->join();
        }

        for(unsigned int i = 0; i < watchdogs.size(); ++i){
            delete watchdogs[i];
        }


        //getting total sum from the one second period
        theLock.lock();
        logfile << "Total traffic                         " << totalPkts << "     " << totalBytes << "        " << totalFlows << std::endl; 
        std::cout << "Total traffic         " << totalPkts << "     " << totalBytes << "        " << totalFlows << std::endl; 
        theLock.unlock();


        //refreshing all total counts
        totalFlows = totalBytes = totalPkts = 0;

        std::this_thread::sleep_for (std::chrono::milliseconds(20));
    }

    exit(0);
    return 0;
}

void watchdog(int watchdogID, int clientSocket){
    theLock.lock();
    int bytesRcv = 0;
    if((bytesRcv = recv(clientSocket, recvBuf, MAXDATASIZE-1,0)) < 0){
        std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
        logfile.close();//TODO: close it only if the size of the clients is == 1
        exit(0);
        return;
    }
    recvBuf[bytesRcv] = '\0';

    processPkt(watchdogID, clientSocket);
    theLock.unlock();
}

void processPkt(int watchdogID, int clientSocket){
    if(strcmp(recvBuf, "close") == 0){
        //removing the watchdog from the table
        clientTable.erase(watchdogID);
        if(clientTable.size() == 0){
            logfile.close();//TODO: close it only if the size of the clients is == 1
            exit(0);
            return;
        }
        theLock.unlock();
    }

    if(recvBuf[0] == 'r'){//normal received pkt
        //parsing data
        int rn;//report number
        int pn;//pkt number
        int bn;//byte number
        int fn;//flow number
        std::stringstream sss;
        std::string notused;
        sss << recvBuf;
        sss >> notused;
        sss >> rn >> pn >> bn >> fn;

        totalBytes += bn; 
        totalFlows += fn;
        totalPkts  += pn;
        
        logfile << "Received report              " << watchdogID << "    " << rn << "    " << pn  << "    " << bn << "     " << fn << std::endl;
        std::cout << "Received report               " << watchdogID << 
        "    " << rn << "    " << pn  << "    " << bn << "     " << fn << std::endl;
    }else if (recvBuf[0] == 'a'){
        //parsing data
        int rn;//report number
        int pn;//pkt number
        int bn;//byte number
        int fn;//flow number
        std::string dstIp;
        std::stringstream sss;
        std::string notused;
        sss << recvBuf;
        sss >> notused;
        sss >> notused;
        sss >> rn >> pn >> bn >> fn >> dstIp;

        totalBytes += bn; 
        totalFlows += fn;
        totalPkts  += pn;
        
        logfile << "Received alert report        " << watchdogID << "    " << rn << "    " << pn  << "    " << bn << "     " << fn << "    " << dstIp << std::endl;
        std::cout << "Received alert report     " << watchdogID << 
        "    " << rn << "    " << pn  << "    " << bn << "     " << fn << "    " << dstIp << std::endl;
    }
}


void parseInput(std::string &writeFileName, int &watchdogsNums, int argv, char **argc) {
    for(int i = 0; i < argv; ++i){
        if(strcmp(argc[i], "-n") == 0){
            watchdogsNums = std::atoi(argc[++i]);
        }else if(strcmp(argc[i], "-w") == 0){
            writeFileName = argc[++i];
        }
    }
}
