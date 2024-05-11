#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

int main(int argc, char *argv[])
{
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    char sendBuff[1025];
    time_t ticks;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, '0', sizeof(sendBuff));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(8000);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 3);
    
    // listen(listenfd, 4096);
    // for a longer queue, Linux will reduce the timeout for entires in the backlog queue
    // dpending on how much "new/young" requests are in the backlog queue
    // for more informaiton, please refer to https://elixir.bootlin.com/linux/v6.1/source/net/ipv4/inet_connection_sock.c#L944
    
    // to fill a longer backlog queue, the attacker has 2 options:
    // 1. send all padding queries every per 4 seconds
    // 2. send qlen/8 + 1 queries every per 1 second, and other queries every per 8 seconds.

    // to try the spoofing and feedback for a longer queue e.g., 4096, try sender_long_backlog.c

    while(1)
    {

        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
        printf("connection accepted\n");
        close(connfd);
    }
}
