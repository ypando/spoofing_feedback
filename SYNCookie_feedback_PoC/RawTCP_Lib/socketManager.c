#include "../include/socketManager.h"

int rawsocket_send(int sock, packet_t packet) {
    struct sockaddr_in sock_in;
    sock_in.sin_addr.s_addr = packet.ipheader->daddr;
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = packet.tcpheader->dest;

    int sent = sendto(sock, packet.packet, packet.ipheader->tot_len, 0, (struct sockaddr*)&sock_in, sizeof(sock_in));

    free(packet.packet);
    if(sent<0){
        perror("ERROR sending the packet in the socket");
        return -1;
    }

    return 0;
}

packet_t rawsocket_sniff(int sock) {
    packet_t packet;

    //Result of recv
    int buffer_size = 20000;
    char* buffer = calloc(buffer_size, sizeof(char));
    int received = recvfrom(sock, buffer, buffer_size, 0x0, NULL, NULL);

    if(received<0){
        //perror("ERROR receiving packet in the socket");
        packet = build_null_packet(packet);
        return packet;
    }

    packet = parse_packet(buffer, buffer_size);

    return packet;
}

packet_t rawsocket_sniff_pattern(char* payload_pattern){
    int pattern_received = 0;
    //Create raw socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    packet_t packet;

    while(!pattern_received){
        if(sock == -1){
            perror("ERROR opening raw socket. Do you have root priviliges?");
            packet = build_null_packet(packet);
            return packet;
        }

        //Result of recv
        int buffer_size = 20000;
        char* buffer = calloc(buffer_size, sizeof(char));
        int received = recvfrom(sock, buffer, buffer_size, 0x0, NULL, NULL);

        if(received<0){
            perror("ERROR receiving packet in the socket");
            packet = build_null_packet(packet);
            return packet;
        }

        packet = parse_packet(buffer, buffer_size);

        if(strncmp(packet.payload, payload_pattern, strlen(payload_pattern)) == 0){
            //printf("Found the packet with the pattern %s\n", payload_pattern);
            pattern_received = 1;
        }else{
            //Not the one we are looking for
            //printf("Found payload string was %s\n", packet.payload);
        }

    }
    close(sock);
    return packet;
}

packet_t build_tcp_packet(
    u_int16_t source_port,
    u_int16_t destination_port,
    const char* source_ip_address,
    const char* destination_ip_address,
    u_int32_t seq,
    u_int32_t ack,
    u_int32_t packet_length,
    char flags,
    char* payload
    ){
        //First we build a TCP header
        struct tcphdr *tcpheader = generate_tcp_header(source_port,destination_port,htonl(seq),htonl(ack),htons(5840));
        if(!tcpheader){
            perror("Could not allocate memory for tcp header");
            exit(1);
        }


        set_segment_flags(tcpheader, flags);
        //tcpheader->th_flags = flags;

        int payload_length = strlen((const char*)payload);
        //We copy the payload we were given, just in case they free memory on the other side
        forge_TCP_checksum(payload_length, source_ip_address, destination_ip_address, tcpheader, payload);
        
        //Now we build the whole packet and incorporate the previous tcpheader + payload
        char *packet = malloc(sizeof(char)*packet_length);
        bzero(packet, packet_length);

        //First we incorporate the IP header
        struct iphdr *ipheader = generate_ip_header(source_ip_address, destination_ip_address, payload_length);
        //The IP header is the first element in the packet
        memcpy(packet, ipheader, sizeof(struct iphdr));
        free(ipheader);
        ipheader = (struct iphdr*) packet;
        //We incorporate the payload, goes after the tcpheader but we need it already for the checksum computation (the tcpheader does not take part)
        memcpy(packet+sizeof(struct iphdr)+sizeof(struct tcphdr), payload, payload_length);
        //free(payload);
        payload = packet+sizeof(struct iphdr)+sizeof(struct tcphdr);
        compute_ip_checksum(ipheader, (unsigned short*) packet, ipheader->tot_len);
        //Now we incorporate the tcpheader
        memcpy(packet+sizeof(struct iphdr), tcpheader, sizeof(struct tcphdr));
        free(tcpheader);
        tcpheader = (struct tcphdr*)(packet+sizeof(struct iphdr));
        
        //We build the returning data structure
        packet_t result;
        result.ipheader = ipheader;
        result.tcpheader = tcpheader;
        result.payload = payload;
        result.packet = packet;
        result.payload_length = payload_length;

        return result;
}
