#ifndef HEADER_SOCKETS
#define HEADER_SOCKETS

#include "packetForger.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "packetInterpreter.h"

int rawsocket_send(int socket, packet_t packet);

packet_t rawsocket_sniff(int socket);

packet_t rawsocket_sniff_pattern(char* payload_pattern);

#endif
