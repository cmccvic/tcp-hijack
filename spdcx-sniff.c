#include "spdcx-sniff.h"

int main(){
    char            errbuf[PCAP_ERRBUF_SIZE];
	char            *device;
    int             datalinkType;
    int             maxBytesToCapture = 65535;
	pcap_t          *packetDescriptor;

	spdcxSniffArgs *sniffArgs;
	if( !(sniffArgs = malloc(sizeof(spdcxSniffArgs))) ){
		fprintf(stderr, "[FAIL] Unable to obtain memory.\n");
		return 1;
	}

    /* Zero out data we will eventually populate: */
	memset(sniffArgs, 0, sizeof(spdcxSniffArgs));
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	/* Find suitable network hardware to monitor: */
	if ( (device = pcap_lookupdev(errbuf)) <= 0 ){
		fprintf(stderr, "[FAIL] pcap_lookupdev returned: \"%s\"\n", errbuf);
		return 1;
	} else printf("[INFO] Found Hardware: %s\n", device);

	/* Obtain a descriptor to monitor the hardware: */
	if ( (packetDescriptor = pcap_open_live(device, maxBytesToCapture, 1, 512, errbuf)) < 0 ){
		fprintf(stderr, "[FAIL] pcap_open_live returned: \"%s\"\n", errbuf);
		return 1;
	} else printf("[INFO] Obtained Socket Descriptor: %d\n", packetDescriptor);

	/* Determine the data link type of the descriptor we obtained: */
    if ((datalinkType = pcap_datalink(packetDescriptor)) < 0 ){
        fprintf(stderr, "[FAIL] pcap_datalink returned: \"%s\"\n", pcap_geterr(packetDescriptor));
        return 2;
    } else printf("[INFO] Obtained Data Link Type: %d\n", datalinkType);
 
    /* Determine the header length of the data link layer: */
    switch (datalinkType) {
	    case DLT_NULL:
	    	sniffArgs->dataLinkOffset = 4;
			printf("Listening on an NULL connection. Data Link Offset: 14\n");
	        break;

	    case DLT_EN10MB:
	    	sniffArgs->dataLinkOffset = 14;
			printf("Listening on an Ethernet connection. Data Link Offset: 14\n");
	        break;
	 
	    case DLT_SLIP:
	    case DLT_PPP:
	    	sniffArgs->dataLinkOffset = 24;
			printf("Listening on an SLIP/PPP connection. Data Link Offset: 14\n");
	        break;
	 
	 	case DLT_IEEE802_11:
	    	sniffArgs->dataLinkOffset = 22;
			printf("Listening on an Wireless connection. Data Link Offset: 22\n");
	        break;
	 	
	    default:
	    	printf("[ERROR]: Unsupported datalink type: %d\n", datalinkType);
	        return 2;
    }

    /* Start the loop: */
	pcap_loop(packetDescriptor, -1, processPacket, (u_char *)sniffArgs);
	return 0;
}


void processPacket(u_char *arg, const struct pcap_pkthdr *pktHeader, const u_char *packet){
    char            ipHeaderInfo[256];
    char            dstIP[256];
    char            srcIP[256];
    int             *packetCounter;
    spdcxSniffArgs  *sniffArgs;
    struct ip       *ipHeader;
    struct icmphdr  *icmpHeader;
    struct tcphdr   *tcpHeader;
    struct udphdr   *udpHeader;
    unsigned short  id;
    unsigned short  seq;

    sniffArgs = (spdcxSniffArgs *)arg;
    packetCounter = &(sniffArgs->packetCount);
    printf("========================================================\n");
	printf("Packet Received: {\"id\":%06d, \"size\":%d}\n", ++(*packetCounter), pktHeader->len);
    printf("--------------------------------------------------------\n");

    /* Navigate past the Data Link layer to the Network layer: */
    packet += sniffArgs->dataLinkOffset;
    ipHeader = (struct ip*)packet;
    strcpy(srcIP, inet_ntoa(ipHeader->ip_src));
    strcpy(dstIP, inet_ntoa(ipHeader->ip_dst));
    sprintf(ipHeaderInfo, "{\"ID\":%d, \"TOS\":0x%x, \"TTL\":%d, \"IpLen\":%d, \"DgLen\":%d}",
            ntohs(ipHeader->ip_id), ipHeader->ip_tos, ipHeader->ip_ttl, 4*ipHeader->ip_hl, ntohs(ipHeader->ip_len));
    printf("NETWORK: %s\n", ipHeaderInfo);

    /* Navigate past the Network layer to the Transport layer: */
    printf("TRANSPORT: ");
    packet += 4*ipHeader->ip_hl;
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr*)packet;
            printf("{\"Protocol\":\"TCP\", \"Src\":\"%s:%d\", \"Dst\":\"%s:%d\",\n", 
                srcIP, ntohs(tcpHeader->source), dstIP, ntohs(tcpHeader->dest));
            printf("\t\"Flags\":\"%c%c%c%c%c%c\", \"Seq\":0x%x, \"Ack\":0x%x, \"Win\":0x%x, \"TcpLen\":%d}\n",
                   (tcpHeader->urg ? 'U' : '*'), (tcpHeader->ack ? 'A' : '*'), (tcpHeader->psh ? 'P' : '*'), 
                   (tcpHeader->rst ? 'R' : '*'), (tcpHeader->syn ? 'S' : '*'), (tcpHeader->fin ? 'F' : '*'),
                   ntohl(tcpHeader->seq), ntohl(tcpHeader->ack_seq), ntohs(tcpHeader->window), 4*tcpHeader->doff);
            break;
     
        case IPPROTO_UDP:
            udpHeader = (struct udphdr*)packet;
            printf("{\"Protocol\":\"UDP\", \"Src\":\"%s:%d\", \"Dst\":\"%s:%d\"}\n", 
                srcIP, ntohs(udpHeader->source), dstIP, ntohs(udpHeader->dest));
            break;
     
        case IPPROTO_ICMP:
            icmpHeader = (struct icmphdr*)packet;
            printf("{\"Protocol\":\"ICMP\", \"Src\":\"%s\", \"Dst\":\"%s\",\n", srcIP, dstIP);
            memcpy(&id, (u_char*)icmpHeader+4, 2);
            memcpy(&seq, (u_char*)icmpHeader+6, 2);
            printf("\t\"Type:\"%d, \"Code\":%d, \"ID\":%d, \"Seq\":%d}\n", 
                icmpHeader->type, icmpHeader->code, ntohs(id), ntohs(seq));
            break;

        default:
            printf("Unsupported Protocol\n");
            break;
    }
    printf("========================================================\n\n");
}

