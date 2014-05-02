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
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "packet-send.h"
#include "packet-sniff.h"

/* Displays the usage string for this program */
void display_usage(char *name);

#endif
