#define _GLIBCXX_USE_NANOSLEEP 1
#include <chrono>
#include <thread>
#include <stdio.h>
#include <stdlib.h>
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
#include <ifaddrs.h>
#include <thread>
#include <signal.h>
#include <sstream>

/*The main structure of this file was taken from Beej's Guide to Network Programming
 * Nonetheless, it is not the same. I used Beej's Guide to Network Programming as a
 * guide*/



#define IMGSIZE 400000

//one global variable
std::ofstream logfile;

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
    logfile << "terminating server..." << std::endl;
    logfile.close();
    exit(0);
}

void parseInput(bool &TCP, bool &UDP, bool &DFLAG, bool &IFLAG, std::string &port, std::string &imagePath,
                std::string &logfileName, int argv, char **argc);

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


    if(argv < 6){
        std::cerr << "usage: server –u –p portno –l logfile"<< std::endl;
        return 1;
    }

    //declaring variables
    //local parsing data
        std::string logfileName;
        std::string imagePath;//this could be a single image or a collection of images
        std::ifstream imageFILE;
        //declaring flags
        bool TCP, UDP, DFLAG, IFLAG;
        TCP = UDP = DFLAG = IFLAG = false;

    //local network related data (local)
    addrinfo hints, *allInfo;
    std::string port;
    int localSocket;
    const char* localIP;
    int backlog = 0;

    //client data (remote)
    addrinfo clientAddr;//when receiving, this address is going to be filled up;
    char clientBuf[250];
    ssize_t clientBufSize;//when data is received from recvfrom, this int will have the size of the buffer void*
    socklen_t clientSockLen;
    char clientIP[INET_ADDRSTRLEN];
    std::string clientIPString;
    int clientSocket;//used for new connections

#if DEBUG
    for(int i = 0; i < argv; ++i){
        std::cout << *(argc+i) << " " << std::endl;
    }
#endif

    //parsing
    parseInput(TCP, UDP, DFLAG, IFLAG, port, imagePath, logfileName, argv, argc);
    if(DFLAG){
        backlog = 1;
    }else{
        backlog = 100;
    }
#if DEBUG
    std::cout << "info after parsing: " <<std::endl;
    std::cout << "TCP: " << TCP << std::endl;
    std::cout << "UDP: " << UDP << std::endl;
    std::cout << "DFLAG: " << DFLAG << std::endl;
    std::cout << "IFLAG: " << IFLAG << std::endl;
    std::cout << "port: " << port << std::endl;
    std::cout << "imagePath: " << imagePath << std::endl;
    std::cout << "logfileName: " << logfileName << std::endl;
#endif
    logfile.open(logfileName);

    //initializing hints (ipv4)
    memset(&hints, 0, (sizeof hints));
    hints.ai_family = AF_INET;
    if(UDP){
        hints.ai_socktype = SOCK_DGRAM;
    }
    if(TCP){
        hints.ai_socktype = SOCK_STREAM;
    }
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
            perror("server: socket");
            allInfo = allInfo->ai_next;
            continue;
        }

        if (bind(localSocket, allInfo->ai_addr, allInfo->ai_addrlen) == -1) {
            close(localSocket);
            perror("server: bind");
            allInfo = allInfo->ai_next;
            continue;
        }
        break;
    }


    //server started or UDP
    if(TCP){
        if(listen(localSocket, backlog) == -1){
            std::cerr << "Problem listening:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        logfile << "server started on " << localIP << " at port " << port << std::endl;
        std::cout << "server started on " << localIP << " at port " << port << std::endl;



        int IDSeter = 1;
        while(1) {  // main accept() loop
            clientSocket = accept(localSocket, (struct sockaddr *)&clientAddr, &clientAddr.ai_addrlen);
            if (clientSocket == -1) {
                perror("accept");
                continue;
            }
            int clientID = IDSeter++;
            inet_ntop(AF_INET,
                      get_in_addr((struct sockaddr *)&clientAddr),
                      clientIP, clientAddr.ai_addrlen);
	    //getting client ip
            //getting uscid
	    int bytesRcv = 0;
            if((bytesRcv = recv(clientSocket, clientIP, 30,0)) < 0){
   	         std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                 logfile.close();
                 return 1;
            }
	    clientIP[bytesRcv] = '\0';

            if(DFLAG){//If it's part three of the assignment
                logfile << "received client connection " << clientID << " from hostname " << clientIP << " port " << port << std::endl;
                std::cout<< "received client connection " << clientID << " from hostname " << clientIP << " port " << port << std::endl;
                if (!fork()) { // this is the child process
                    close(localSocket); // child doesn't need the listener

                    int realNumberBytes = 0;
                    char buf[1024];

                    //Telling the client it's part three
                    std::stringstream ss1;
                    std::string acceptBuf;
                    ss1 << clientID;
                    ss1 >> acceptBuf;
                    acceptBuf = "y" + acceptBuf;
                    if(send(clientSocket, acceptBuf.c_str(), acceptBuf.length(), 0) < 0) {
                        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        return 1;
                    }

                    //getting uscid
                    if((realNumberBytes = recv(clientSocket, buf, 1024,0)) < 0){
                        std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        return 1;
                    }
                    buf[realNumberBytes] = '\0';
                    logfile << clientID << " received " << buf << std::endl;
                    std::cout << clientID << " received " << buf << std::endl;

                    //getting name
                    if((realNumberBytes = recv(clientSocket, buf, 1024,0)) < 0){
                        std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        return 1;
                    }
                    buf[realNumberBytes] = '\0';
                    logfile << clientID << " received " << buf << std::endl;
                    std::cout << clientID << " received " << buf << std::endl;

                    //waiting just for a little bit
                    //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
                    std::this_thread::sleep_for (std::chrono::seconds(1));
                    //


                    //reading image
                    imageFILE.open(imagePath, std::ifstream::binary | std::ifstream::in);
                    std::streampos begin, end;
                    begin = imageFILE.tellg();
                    imageFILE.seekg (0, imageFILE.end);
                    end = imageFILE.tellg();

                    long long int imgSize = end - begin;
                    char imgBuf[400000];
                    imageFILE.seekg (0, imageFILE.beg);
                    for(int i= 0; i < 400000; ++i){
                        imgBuf[i] = 'i';
                    }
                    int i = 0;
                    while(imageFILE.get(imgBuf[i++]));
                    imageFILE.close();
                    logfile << clientID <<" sending image file " << imagePath << std::endl;
                    std::cout << clientID <<" sending image file " << imagePath << std::endl;

                    //first send the image size
                    std::stringstream ss;
                    std::string temp;
                    ss << imgSize;
                    ss >> temp;
                    if(send(clientSocket, temp.c_str(), temp.length(), 0) < 0) {
                        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        return 1;
                    }

                    while(true){
                        if(send(clientSocket, imgBuf, imgSize, 0) < 0) {
                            std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                            logfile.close();
                            return 1;
                        }

                        if((realNumberBytes = recv(clientSocket, buf, 1024,0)) < 0){
                            std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                            logfile.close();
                            return 1;
                        }
                        buf[realNumberBytes] = '\0';

                        if(strcmp("yes", buf) == 0){
                            break;
                        }
                    }
                    logfile << clientID << " terminating client connection..." << std::endl;
                    std::cout << clientID << " terminating client connection..." << std::endl;
                    close(clientSocket);
                    return 0;
                }
            }
            else{//If it's part two of the assignment
                logfile << "received client connection from hostname " << clientIP << " port " << port << std::endl;
                std::cout<< "received client connection from hostname " << clientIP << " port " << port << std::endl;

                int realNumberBytes = 0;
                char buf[1024];

                //telling client it's part 2
                if(send(clientSocket, "n", 1, 0) < 0) {
                    std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                    logfile.close();
                    return 1;
                }


                //getting uscid
                if((realNumberBytes = recv(clientSocket, buf, 1024,0)) < 0){
                    std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                    logfile.close();
                    return 1;
                }
                buf[realNumberBytes] = '\0';
                logfile << "received " << buf << std::endl;
                std::cout << "received " << buf << std::endl;

                //getting name
                if((realNumberBytes = recv(clientSocket, buf, 1024,0)) < 0){
                    std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                    logfile.close();
                    return 1;
                }
                buf[realNumberBytes] = '\0';
                logfile << "received " << buf << std::endl;
                std::cout << "received " << buf << std::endl;

                //waiting just for a little bit
                //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
                std::this_thread::sleep_for (std::chrono::seconds(1));
                //


                //reading image
                imageFILE.open(imagePath, std::ifstream::binary | std::ifstream::in);
                std::streampos begin, end;
                begin = imageFILE.tellg();
                imageFILE.seekg (0, imageFILE.end);
                end = imageFILE.tellg();

                long long int imgSize = end - begin;
                char imgBuf[400000];
                imageFILE.seekg (0, imageFILE.beg);
                for(int i= 0; i < 400000; ++i){
                    imgBuf[i] = 'i';
                }
                int i = 0;
                while(imageFILE.get(imgBuf[i++]));
                imageFILE.close();
                logfile <<"sending image file " << imagePath << std::endl;
                std::cout <<"sending image file " << imagePath << std::endl;

                //first send the image size
                std::stringstream ss;
                std::string temp;
                ss << imgSize;
                ss >> temp;
                if(send(clientSocket, temp.c_str(), temp.length(), 0) < 0) {
                    std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                    logfile.close();
                    return 1;
                }

                while(true){
                    if(send(clientSocket, imgBuf, imgSize, 0) < 0) {
                        std::cerr << "Problem sending TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        return 1;
                    }

                    if((realNumberBytes = recv(clientSocket, buf, 1024,0)) < 0){
                        std::cerr << "Problem receiving TCP message:" << std::endl << strerror(errno) << std::endl;
                        logfile.close();
                        return 1;
                    }
                    buf[realNumberBytes] = '\0';

                    if(strcmp("yes", buf) == 0){
                        break;
                    }
                }
                logfile << "terminating server..." << std::endl;
			    std::cout << "terminating server..." << std::endl;
			    logfile.close();

			    //closing sockets
	            close(clientSocket);
	            close(localSocket);
	            return 0;
            }
        }
    }else if(UDP){
        logfile << "server started on " << localIP << " at port " << port << std::endl;
        std::cout << "server started on " << localIP << " at port " << port << std::endl;

	//receiving the client ip
        clientSockLen = sizeof(sockaddr_storage);
	if ((clientBufSize = recvfrom(localSocket, clientBuf, 250, 0, clientAddr.ai_addr, &clientSockLen)) < 0) {
            std::cerr << "Problem receiving message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
	clientBuf[clientBufSize] = '\0';
	clientIPString = std::string(clientBuf);
	std::cout << "received client connection from hostname "<< clientBuf <<" at port "<< port << std::endl;


        //receiving part
        //first the USCID
        clientSockLen = sizeof(sockaddr_storage);
        if ((clientBufSize = recvfrom(localSocket, clientBuf, 250, 0, clientAddr.ai_addr, &clientSockLen)) < 0) {
            std::cerr << "Problem receiving message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        //setting and end to the message so the it does not prints garbage
        clientBuf[clientBufSize] = '\0';
        //getting client IP
        //clientIPString = inet_ntop(AF_INET, get_in_addr((struct sockaddr *) &clientAddr), clientIP, sizeof clientIP);
        logfile << "received " << clientBuf << std::endl;
        std::cout << "received " << clientBuf << std::endl;




        //second: the Name
        clientSockLen = sizeof(sockaddr_storage);
        if ((clientBufSize = recvfrom(localSocket, clientBuf, 250, 0, clientAddr.ai_addr, &clientSockLen)) < 0) {
            std::cerr << "Problem receiving message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        //setting and end to the message so the it does not prints garbage
        clientBuf[clientBufSize] = '\0';
        //getting client IP
        logfile << "received " << clientBuf << std::endl;
        std::cout << "received " << clientBuf << std::endl;




        //third I send back the random string

        //third part1: Get info from client
        addrinfo hints2, *allInfo2;
        int localSocket2;

        memset(&hints2, 0, sizeof(hints2));
        hints2.ai_family = AF_INET;
        hints2.ai_socktype = SOCK_DGRAM;

        if ((getaddrinfo(clientIPString.c_str(), "2222", &hints2, &allInfo2)) != 0) {
            std::cerr << "Problem getting address info:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }

        tryagain2:
        if (allInfo2->ai_family == AF_INET) {
            if ((localSocket2 = socket(allInfo2->ai_family, allInfo2->ai_socktype, allInfo2->ai_protocol)) < 0) {
                std::cerr << "Problem getting local socket file descriptor:" << std::endl;
                logfile.close();
                return 1;
            }
        } else {//in case of AF_INET6
            if (allInfo2 != NULL) {
                allInfo2 = allInfo->ai_next;
                goto tryagain2;
            } else {//no PF_INET
                std::cerr << "There might not be an PF_INET fot this computer?" << std::endl;
                logfile.close();
                return 1;
            }
        }


        //waiting just for a little bit
        //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
        std::this_thread::sleep_for (std::chrono::seconds(1));
        //

        //third part 2: sending back
        std::string rstr = randomString();
        //sending back the random string
        logfile << "sending random string length " << rstr.length() - 8 << std::endl;
        std::cout << "sending random string length " << rstr.length() - 8 << std::endl;
        int realNumberBytes;
        if ((realNumberBytes = sendto(localSocket2, rstr.c_str(), rstr.length(), 0, allInfo2->ai_addr, allInfo2->ai_addrlen)) < 0) {//0 means no flags
            std::cerr << "Problem sending message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }



        //confirming string length from client
        clientSockLen = sizeof(sockaddr_storage);
        if ((clientBufSize = recvfrom(localSocket, clientBuf, 250, 0, clientAddr.ai_addr, &clientSockLen)) < 0) {
            std::cerr << "Problem receiving message:" << std::endl << strerror(errno) << std::endl;
            logfile.close();
            return 1;
        }
        //setting and end to the message so the it does not prints garbage
        clientBuf[clientBufSize] = '\0';
        char* strlength = clientBuf + strlen("StringLength ");
        logfile << "received string length of " << strlength << std::endl;
        std::cout << "received string length of " << strlength << std::endl;


        //waiting just for a little bit
        //taken from http://www.cplusplus.com/reference/thread/this_thread/sleep_for/
        std::this_thread::sleep_for (std::chrono::seconds(1));
        //
    }
    logfile << "terminating server..." << std::endl;
    std::cout << "terminating server..." << std::endl;
    logfile.close();

    exit(0);
    return 0;
}


void parseInput(bool &TCP, bool &UDP, bool &DFLAG, bool &IFLAG, std::string &port, std::string &imagePath,
                std::string &logfileName, int argv, char **argc) {
    for(int i = 0; i < argv; ++i){
        if(strcmp(argc[i], "-t") == 0){
            TCP = true;
            UDP = !TCP;
        }else if(strcmp(argc[i], "-u") == 0){
            UDP = true;
            TCP = !UDP;
        }else if(strcmp(argc[i], "-p") == 0){
            port = argc[++i];
        }else if(strcmp(argc[i], "-l") == 0){
            logfileName = argc[++i];
        }else if(strcmp(argc[i], "-i") == 0){
            IFLAG = true;
            DFLAG = !IFLAG;
            imagePath = argc[++i];
        }else if(strcmp(argc[i], "-d") == 0){
            DFLAG = true;
            IFLAG = !DFLAG;
            imagePath = argc[++i];
        }
    }
}

std::string randomString() {
    int r = rand()%150 + 100;
    char rstr[r + 8 + 1];

    for(int i = 0; i < (r + 8); ++i){
        if(i == 0){
            rstr[i] = 'R';
        }else if(i == 1){
            rstr[i] = 'S';
        }else if(i == 2){
            rstr[i] = 'T';
        }else if(i == 3){
            rstr[i] = 'R';
        }else if(i == 4){
            rstr[i] = 'I';
        }else if(i == 5){
            rstr[i] = 'N';
        }else if(i == 6){
            rstr[i] = 'G';
        }else if(i == 7){
            rstr[i] = ' ';
        }else {
            rstr[i] = (char) (rand() % (126 - 32) + 32);
        }
    }
    rstr[r + 8] = '\0';
    return std::string(rstr);
}
