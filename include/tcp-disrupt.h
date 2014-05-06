#ifndef TCP_DISRUPT_H
#define TCP_DISRUPT_H

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>

#include "packet-send.h"
#include "packet-sniff.h"

#define ACK_ON 1
#define SYN_ON 1
#define RESET_ON 1

#define ACK_OFF 0
#define SYN_OFF 0
#define RESET_OFF 0

/* Displays the usage string for this program */
void display_usage(char *name);

void disrupt_session(char *sourceIP, uint16_t sourcePort, char *destinationIP, uint16_t destinationPort, uint32_t sequenceNumber, uint32_t ackNumber, int timestamp, int finalRound)

#endif
