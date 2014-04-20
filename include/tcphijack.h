#ifndef TCPHIJACK_H
#define TCPHIJACK_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h> //memset()
#include <unistd.h> //sleep()

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

#endif