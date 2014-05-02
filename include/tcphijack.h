#ifndef TCPHIJACK_H
#define TCPHIJACK_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h> //memset()
#include <unistd.h> //sleep()
#include <stdint.h>

//Socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//IP header (struct iphdr) definition
#include <linux/ip.h>
//TCP header (struct tcphdr) definition
#include <linux/tcp.h>

//Perhaps these headers are more general
//#include <netinet/tcp.h>
//#include <netinet/ip.h>


void gen_packet(  char *srcIP,
                  char *dstIP,
                  u_int16_t dstPort,
                  u_int16_t srcPort,
                  u_int32_t syn,
                  u_int16_t ack,
                  u_int32_t seq,
                  u_int32_t ack_seq,
                  char data,
                  char *packet,
                  uint32_t packet_size);

void send_packet(int socket_fd, char *packet, struct sockaddr_in addr_in);

//Calculate the TCP header checksum of a string (as specified in rfc793)
//Function from http://www.binarytides.com/raw-sockets-c-code-on-linux/
unsigned short csum(unsigned short *ptr,int nbytes);

//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};


#endif