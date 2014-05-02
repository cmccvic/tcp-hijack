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


/* Default values to use if either host's details are not provided. */
#define DEFAULT_CLIENT_IP   "192.168.1.106"
#define DEFAULT_SERVER_IP   "192.168.1.113"
#define DEFAULT_SERVER_PORT "23"


/* Standard header sizes for different transport layer protocols. */
#define UDP_HEADER_SIZE 8
#define TCP_HEADER_SIZE 20


/* DNS Header bit flags as defined in RFC1035. */
#define DNS_HEADER_QR_QUERY                 0x0000
#define DNS_HEADER_QR_RESPONSE              0x8000
#define DNS_HEADER_OPCODE_QUERY             0x0000
#define DNS_HEADER_OPCODE_STATUS            0x1000
#define DNS_HEADER_OPCODE_IQUERY            0x0800
#define DNS_HEADER_FLAG_AA                  0x0400
#define DNS_HEADER_FLAG_TC                  0x0200
#define DNS_HEADER_FLAG_RD                  0x0100
#define DNS_HEADER_FLAG_RA                  0x0080
#define DNS_HEADER_RCODE_NO_ERROR           0x0000
#define DNS_HEADER_RCODE_FORMAT_ERROR       0x0001
#define DNS_HEADER_RCODE_SERVER_FAILURE     0x0002
#define DNS_HEADER_RCODE_NAME_RROR          0x0003
#define DNS_HEADER_RCODE_NOT_IMPLEMENTED    0x0004
#define DNS_HEADER_RCODE_REFUSED            0x0005


/* Struct pcap_loop will use to pass arguments to our packet processing function. */
typedef struct spdcxSniffArgs{
    int packetCount;
    int dataLinkOffset;
} spdcxSniffArgs;


/* DNS header as defined in RFC1035 */
typedef struct dnsHeader{
    int16_t id;
    int16_t flags;
    int16_t qdCount;
    int16_t anCount;
    int16_t nsCount;
    int16_t arCount;
} dnsHeader;


/* Called by pcap_loop. Parse and process incoming packets. */
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);


/* Using the network interface provided, disrupt the  TCP session between the client
 * and server. Providing a NULL to the network interface argument will allow the
 * pcap library to automatically select a device on the computer.
 *
 * Returns: 0 on Success
 *          1 on Failure
 */
int tcpDisrupt(char *clientIP, char *serverIP, char *serverPort, char *networkInterface);


#endif