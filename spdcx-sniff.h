#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

/* Struct pcap_loop will use to pass arguments to our packet processing function. */
typedef struct spdcxSniffArgs {
	int packetCount;
	int dataLinkOffset;
} spdcxSniffArgs;

/* Called by pcap_loop. Parse and process incoming packets. */
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);