#include <iostream>
#include <string>
#include <pcap.h>


//Global variables

//user input
std::string filename, logfile, interface;
bool p, b, s, d;//flags


//func signatures
bool parseInput(int argv, char** argc);//parses input
void printParsedResults();//prints results

int main(int argv, char** argc) {
    p = b = s = d = false;

    if(parseInput(argv, argc)){
        std::cout << "usage: balancer [-r filename] [-i interface] [ -l filename ] " << 
                        "[-p] [-b] [-s] [-d] \n or \n" << 
                        "./balancer [-r filename] [-i interface] " <<
                        "[-w num] [ -l filename ] [-c configpercent]" << std::endl;
        return 1;
    }



    return 0;
}

bool parseInput(int argv, char** argc){
    #if DEBUGPARSE
        for(int i = 0; i < argv; ++i){
            std::cout << *(argc+i) << " " << std::endl;
        }
    #endif


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
                #if DEBUGPARSE
                    std::cout << "-p = true" << argc[i] << std:: endl;
                #endif
                continue;
            }else if(strcmp(argc[i], "-b") == 0){
                b = true;
                #if DEBUGPARSE
                    std::cout << "-b = true" << argc[i] << std:: endl;
                #endif
                continue;
            }else if(strcmp(argc[i], "-s") == 0){
                s = true;
                #if DEBUGPARSE
                    std::cout << "-s = true: " << std:: endl;
                #endif
                continue;
            }else if (strcmp(argc[i], "-d")){
                d = true;
                #if DEBUGPARSE
                    std::cout << "-d = true" << argc[i] << std:: endl;
                #endif
                continue;
            }
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
















