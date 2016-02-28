#define _GLIBCXX_USE_NANOSLEEP 1
#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <unistd.h>
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
#include <sstream>

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

void parseInput(bool &TCP, bool &UDP, std::string &port, std::string &imagePath, std::string& serverIP, std::string &logfileName, char **argc, int argv);

#define MAXDATASIZE 1024

int main(int argv, char* argc[]){//client –u –s serverIP –p portno –l logfile

    //variables declaration
    //local parsing data
    bool UDP, TCP;
    std::ofstream logfile;
    std::ofstream imageFILE;
    std::string imagePath, logfileName;
    UDP = TCP = false;

    //client (local/me) data
    addrinfo hints, *allInfo;
    int localSocket = 0;
    std::string localBuf;
    int realNumberBytes;
    const char* myIP;

    //server (remote) data
    std::string serverIP;
    std::string port;
    char hostname[1024], hostservice[20];



#if DEBUG
    for(int i = 0; i < argv; ++i){
        std::cout << *(argc+i) << " " << std::endl;
    }
#endif

    if(argv < 8){
        std::cerr << "usage: client –u –s serverIP –p portno –l logfile"<< std::endl;
        return 1;
    }

    //parsing input
    parseInput(TCP, UDP, port, imagePath, serverIP, logfileName, argc, argv);

#if DEBUG
    std::cout << "info after parsing: " <<std::endl;
    std::cout << "TCP: " << TCP << std::endl;
    std::cout << "UDP: " << UDP << std::endl;
    std::cout << "port: " << port << std::endl;
    std::cout << "logfileName: " << logfileName << std::endl;
    std::cout << "serverIP: " << serverIP << std::endl;
    std::cout << "imagePath: " << imagePath << std::endl;
    std::cout << "argv: " << argv << std::endl;
#endif

    //opening logfile
    logfile.open(logfileName);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if(UDP) {
        hints.ai_socktype = SOCK_DGRAM;
    }else if(TCP){
        hints.ai_socktype = SOCK_STREAM;
    }

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


    logfile << "conencting to the server " + serverIP + " at port " + port << std::endl;
    std::cout << "conencting to the server " + serverIP + " at port " + port << std::endl;

    if(getaddrinfo(serverIP.c_str(), port.c_str(), &hints, &allInfo) < 0){
        std::cerr << "Problem getting address info:" << std::endl << strerror(errno) << std::endl;
        logfile.close();
        return 1;
    }

    //getting the rest of the connection set up

    while(allInfo != NULL){
        if ((localSocket = socket(allInfo->ai_family, allInfo->ai_socktype,
                             allInfo->ai_protocol)) == -1) {
            perror("client: socket");
            allInfo = allInfo->ai_next;
            continue;
        }
        if(TCP) {
            if (connect(localSocket, allInfo->ai_addr, allInfo->ai_addrlen) == -1) {
                close(localSocket);
                perror("client: connect");
                allInfo = allInfo->ai_next;
                continue;
            }
        }
        break;
    }


    //getting names from the host
    getnameinfo(allInfo->ai_addr, allInfo->ai_addrlen, hostname, sizeof hostname, hostservice, sizeof hostservice, 0);


    //sending
    if(TCP){


        //sending my ip
        localBuf = std::string(myIP);
        if(send(localSocket, localBuf.c_str(), localBuf.length(), 0) < 0){
            std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }



        //first figure out if it's part two or three
        char acceptBuf[10];
        if((realNumberBytes = recv(localSocket, acceptBuf, 9,0)) < 0){
            std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        acceptBuf[realNumberBytes] = '\0';

        //Do I have an id?
        if(acceptBuf[0] == 'y'){
            logfile << "connected to the server hostname " << hostname << " received " << acceptBuf+1 << std::endl;
            std::cout << "connected to the server hostname " << hostname << " received " << acceptBuf+1 << std::endl;
        }else{
            logfile << "connected to the server hostname " << hostname << std::endl;
            std::cout << "connected to the server hostname " << hostname << std::endl;
        }





        localBuf = "USCID 58944165389";
        logfile << "Sending " << localBuf << std::endl;
        std::cout << "Sending " << localBuf << std::endl;
        if(send(localSocket, localBuf.c_str(), localBuf.length(), 0) < 0){
            std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }

        //waiting just for a little bit
        //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
        std::this_thread::sleep_for (std::chrono::seconds(1));
        //
        localBuf = "Name Albert Prego";
        logfile << "Sending " << localBuf << std::endl;
        std::cout << "Sending " << localBuf << std::endl;
        if(send(localSocket, localBuf.c_str(), localBuf.length(), 0) < 0) {
            std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }


        //receiving image size
        char imgSizeBuf[7];
        long long int imgSize;
        if((realNumberBytes = recv(localSocket, imgSizeBuf, 6,0)) < 0){
            std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        imgSizeBuf[realNumberBytes] = '\0';
        std::stringstream ss;
        ss << imgSizeBuf;
        ss >> imgSize;

#if DEBUGIMAGE
        std::cout << "expected image size " << imgSize << std::endl;
#endif

        imageFILE.open(imagePath);
        char imgBuf[400000];
        //will loop and request the image until the size requested is the size provided
        while(true){
            if ((realNumberBytes = recv(localSocket, imgBuf, 400000, 0)) < 0) {
                std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                logfile.close();
                return 1;
            }

            if(realNumberBytes != imgSize){
                localBuf = "no";
                if(send(localSocket, localBuf.c_str(), localBuf.length(), 0) < 0){
                    std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                    logfile.close();
                    return 1;
                }
#if DEBUGIMAGE
                std::cout << "Image size received " << realNumberBytes << std::endl;
#endif
                continue;
            }
            localBuf = "yes";
            if(send(localSocket, localBuf.c_str(), localBuf.length(), 0) < 0){
                std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                logfile.close();
                return 1;
            }
#if DEBUGIMAGE
            std::cout << "Image size received " << realNumberBytes << std::endl;
#endif
            break;

        }
        imgBuf[realNumberBytes] = '\0';

        //writing the image received to file
        int i = 0;
        while(i < realNumberBytes){
            imageFILE << imgBuf[i];
            ++i;
        }
        imageFILE.close();
        logfile << "received image and saved in " << imagePath << std::endl;
        std::cout << "received image and saved in " << imagePath << std::endl;


        logfile << "terminating client..." << std::endl;
        std::cout << "terminating client..." << std::endl;
    }else if(UDP){
        logfile << "connected to the server hostname " << hostname << std::endl;
        std::cout << "connected to the server hostname " << hostname << std::endl;


       //sending my ip address
	localBuf = std::string(myIP);
        if((realNumberBytes = sendto(localSocket, localBuf.c_str(), strlen(localBuf.c_str()), 0, allInfo->ai_addr, allInfo->ai_addrlen)) < 0){//0 means no flags
            std::cerr << "Problem sending message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }



        localBuf = "USCID 589516231\0";
        logfile << "Sending " << localBuf << std::endl;
        std::cout << "Sending " << localBuf << std::endl;

        if((realNumberBytes = sendto(localSocket, localBuf.c_str(), strlen(localBuf.c_str()), 0, allInfo->ai_addr, allInfo->ai_addrlen)) < 0){//0 means no flags
            logfile.close();
            return 1;
        }

        //waiting just for a little bit
        //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
        std::this_thread::sleep_for (std::chrono::seconds(1));
        //


        localBuf = "Name Albert Prego\0";
        logfile << "Sending " << localBuf << std::endl;
        std::cout << "Sending " << localBuf << std::endl;

        if((realNumberBytes = sendto(localSocket, localBuf.c_str(), strlen(localBuf.c_str()), 0, allInfo->ai_addr, allInfo->ai_addrlen)) < 0){//0 means no flags
            std::cerr << "Problem sending message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }




        //time to get the random string
        //part one: able to receive
        //variables
        addrinfo hints2, *allInfo2;
        int localSocket2;

        memset(&hints2, 0, (sizeof hints2));
        hints2.ai_family = AF_INET;
        if(UDP){
            hints2.ai_socktype = SOCK_DGRAM;
        }
        if(TCP){
            hints2.ai_socktype = SOCK_STREAM;
        }
        hints2.ai_flags = 0;


	std::cout << "myIP: " << myIP << std::endl;
        if(getaddrinfo(myIP, "2222", &hints2, &allInfo2) < 0){
            std::cerr << "Problem getting local address info:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }

        //getting the local socket file descriptor
        tryagain2:
        if(allInfo2->ai_family == AF_INET){
            if((localSocket2 = socket(PF_INET, SOCK_DGRAM, allInfo2->ai_protocol)) < 0){
                std::cerr << "Problem getting local socket file descriptor:" <<std::endl << strerror(errno) <<std::endl;
                logfile.close();
                return 1;
            }

            //connecting the local file descriptor with current program
            if(bind(localSocket2, allInfo2->ai_addr, allInfo2->ai_addrlen) != 0){
                std::cerr << "Problem binding socket and port:" << std::endl << strerror(errno) << std::endl;
                logfile.close();
                return 1;
            }
        }else{//in case it's AF_INET6
            if(allInfo2 != NULL){
                allInfo2 = allInfo2->ai_next;
                goto tryagain2;
            }else{
                logfile.close();
                return 1;
            }
        }

        socklen_t clientSockLen = sizeof(sockaddr_storage);
        int clientBufSize2;
        char clientBuf[250];
        addrinfo clientAddr;
        if ((clientBufSize2 = recvfrom(localSocket2, clientBuf, 250, 0, clientAddr.ai_addr, &clientSockLen)) < 0) {
            std::cerr << "Problem receiving message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        //setting and end to the message so the it does not prints garbage
        clientBuf[clientBufSize2] = '\0';
        char* pppp = clientBuf + 8;
        logfile << "received string " << pppp << std::endl;
        std::cout << "received string " << pppp << std::endl;



        //waiting just for a little bit
        //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
        std::this_thread::sleep_for (std::chrono::seconds(1));
        //


        std::stringstream ss;
        int l = strlen(pppp);
        std::string temp;
        ss << l;
        ss >> temp;
        localBuf = "StringLength " + temp;
        logfile << "sending string length " << temp << std::endl;
        std::cout << "sending string length " << temp << std::endl;

        if((realNumberBytes = sendto(localSocket, localBuf.c_str(), strlen(localBuf.c_str()), 0, allInfo->ai_addr, allInfo->ai_addrlen)) < 0){//0 means no flags
            std::cerr << "Problem sending message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }


        //waiting just for a little bit
        //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
        std::this_thread::sleep_for (std::chrono::seconds(1));
        //

        //terminating client
        logfile << "terminating client..." << std::endl;
        std::cout << "terminating client..." << std::endl;
    }
    logfile.close();
    return 0;
}

void parseInput(bool &TCP, bool &UDP, std::string &port, std::string& imagePath,
                std::string& serverIP, std::string &logfileName, char **argc, int argv) {
#if DEBUGPARSE
    std::cout << "inside parseInput()" << std::endl;
#endif
    for(int i = 0; i < argv; ++i){
#if DEBUGPARSE
        std::cout << "argc[" << i << "]: " << argc[i] << std:: endl;
        std::cout << "-t" << strcmp(argc[i], "-t") << std::endl;
        std::cout << "-u" << strcmp(argc[i], "-u") << std::endl;
        std::cout << "-p" << strcmp(argc[i], "-p") << std::endl;
        std::cout << "-l" << strcmp("-l", "-l") << std::endl;
        std::cout << "-i" << strcmp(argc[i], "-i") << std::endl;
        std::cout << "-s" << strcmp(argc[i], "-s") << std::endl;
#endif
        if(strcmp(argc[i], "-t") == 0){
            TCP = true;
            UDP = !TCP;
        }else if(strcmp(argc[i], "-u") == 0){
            UDP = true;
            TCP = !UDP;
        }else if(strcmp(argc[i], "-p") == 0){
            port = argc[++i];
#if DEBUGPARSE
            std::cout << "inside port: " << port << std:: endl;
#endif
        }else if(strcmp(argc[i], "-l") == 0){
            logfileName = argc[++i];
#if DEBUGPARSE
            std::cout << "inside argc[" << i << "]: " << argc[i] << std:: endl;
#endif
        }else if(strcmp(argc[i], "-i") == 0){
            imagePath = argc[++i];
#if DEBUGPARSE
            std::cout << "inside argc[" << i << "]: " << argc[i] << std:: endl;
#endif
        }else if(strcmp(argc[i], "-s") == 0){
            serverIP = argc[++i];
#if DEBUGPARSE
            std::cout << "inside argc[" << i << "]: " << argc[i] << std:: endl;
#endif
        }
    }
}
