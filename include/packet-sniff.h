#ifndef PACKET_SNIFF_H
#define PACKET_SNIFF_H


/* Include dependencies. */
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


typedef int (*packetHandlerFunction)(void *packet, int packetNumber);

typedef struct sniffArgs{
    packetHandlerFunction packetHandlerFunction;
    char *clientIP;
    char *serverIP;
    int   serverPort;
    char *interface;
    char *filterString;
} sniffArgs;


/* Struct pcap_loop will use to pass arguments to our packet processing function. */
typedef struct processPacketArgs{
	char *clientIP;
	char *serverIP;
    int   serverPort;
    int   packetCount;
    int   dataLinkOffset;
} processPacketArgs;


/* DNS header as defined in RFC1035 */
typedef struct dnsHeader{
    int16_t id;
    int16_t flags;
    int16_t qdCount;
    int16_t anCount;
    int16_t nsCount;
    int16_t arCount;
} dnsHeader;


/* Using the network interface provided, sniff network between the client
 * and server. Providing a NULL to the network interface argument will allow the
 * pcap library to automatically select a device on the computer.
 *
 * Returns: 0 on Success
 *          1 on Failure
 */
int sniffNetwork(sniffArgs *sniffArgs);


/* Called by pcap_loop. Parse and process incoming packets. */
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);


#endif