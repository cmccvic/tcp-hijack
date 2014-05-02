#include "spdcx-sniff.h"

//#define SAMPLE_FILTER "tcp and port 80"
//#define SAMPLE_FILTER "udp and port 53"
#define SAMPLE_FILTER ""

int main(int argc, char const *argv[]){
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                packetFilterString[128];
	char                *device;
    int                 datalinkType;
    int                 maxBytesToCapture = 65535;
	pcap_t              *packetDescriptor;
    struct bpf_program  packetFilter;
    uint32_t            srcIP;
    uint32_t            netmask;

	spdcxSniffArgs *sniffArgs;
	if( !(sniffArgs = malloc(sizeof(spdcxSniffArgs))) ){
		fprintf(stderr, "[FAIL] Unable to obtain memory.\n");
		return 1;
	}

    /* Initialize data: */
	memset(sniffArgs, 0, sizeof(spdcxSniffArgs));
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    memset(packetFilterString, 0, 128);
    strncpy(packetFilterString, SAMPLE_FILTER, 127);

	/* Find suitable network hardware to monitor: */
	if(argc < 2) {	
		if ( (device = pcap_lookupdev(errbuf)) <= 0 ){
			fprintf(stderr, "[FAIL] pcap_lookupdev returned: \"%s\"\n", errbuf);
	        free(sniffArgs);
			return 1;
		} else printf("[INFO] Found Hardware: %s\n", device);
	} else {
		device = (char*) argv[1];
	}

    /* Obtain a descriptor to monitor the hardware: */
    if ( (packetDescriptor = pcap_open_live(device, maxBytesToCapture, 1, 512, errbuf)) < 0 ){
        fprintf(stderr, "[FAIL] pcap_open_live returned: \"%s\"\n", errbuf);
        free(sniffArgs);
        return 1;
    } else printf("[INFO] Obtained Socket Descriptor.\n");

	/* Determine the data link type of the descriptor we obtained: */
    if ((datalinkType = pcap_datalink(packetDescriptor)) < 0 ){
        fprintf(stderr, "[FAIL] pcap_datalink returned: \"%s\"\n", pcap_geterr(packetDescriptor));
        free(sniffArgs);
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
            free(sniffArgs);
	        return 2;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcIP, &netmask, errbuf) < 0){
        printf("[FAIL] pcap_lookupnet returned: \"%s\"\n", errbuf);
        free(sniffArgs);
        return 1;
    } else printf("[INFO] Source IP/Netmask: 0x%x/0x%x\n", srcIP, netmask);

    // Convert the packet filter epxression into a packet  filter binary.
    if (pcap_compile(packetDescriptor, &packetFilter, packetFilterString, 0, netmask)){
        printf("[FAIL] pcap_compile returned: \"%s\"\n", pcap_geterr(packetDescriptor));
        free(sniffArgs);
        return 1;
    } 

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(packetDescriptor, &packetFilter) < 0) {
        printf("[FAIL] pcap_setfilter returned: \"%s\"\n", pcap_geterr(packetDescriptor));
        free(sniffArgs);
        return 1;
    } else printf("[INFO] Packet Filter: %s\n", packetFilterString);

    /* Start the loop: */
	pcap_loop(packetDescriptor, -1, processPacket, (u_char *)sniffArgs);
    free(sniffArgs);
	return 0;
}


void processPacket(u_char *arg, const struct pcap_pkthdr *pktHeader, const u_char *packet){
    char            dstIP[256];
    char            srcIP[256];
    int             dataLength;
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
    dataLength = ntohs(ipHeader->ip_len) - (4 * ipHeader->ip_hl);
    strcpy(srcIP, inet_ntoa(ipHeader->ip_src));
    strcpy(dstIP, inet_ntoa(ipHeader->ip_dst));

    printf("NETWORK:\n\t{");
    printf("\"ID\":%d, ", ntohs(ipHeader->ip_id));
    printf("\"Service Type\":0x%x, ", ipHeader->ip_tos);
    printf("\"TTL\":%d, ", ipHeader->ip_ttl);
    printf("\"Header Length\":%d, ", 4 * ipHeader->ip_hl);
    printf("\"Total Length\":%d", ntohs(ipHeader->ip_len));
    printf("}\n");

    /* Navigate past the Network layer to the Transport layer: */
    packet += 4 * ipHeader->ip_hl;
    printf("TRANSPORT:\n\t{");
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr*)packet;
            dataLength = dataLength - TCP_HEADER_SIZE;
            packet += TCP_HEADER_SIZE;
            printf("\"Protocol\":\"TCP\", ");
            printf("\"Source\":\"%s:%d\", ", srcIP, ntohs(tcpHeader->source));
            printf("\"Destination\":\"%s:%d\", ", dstIP, ntohs(tcpHeader->dest));
            printf("\"Flags\":\"");
            printf("%s", (tcpHeader->syn ? "SYN|"   : ""));
            printf("%s", (tcpHeader->ack ? "ACK|"   : ""));
            printf("%s", (tcpHeader->fin ? "FIN|"   : ""));
            printf("%s", (tcpHeader->psh ? "PUSH|"  : ""));
            printf("%s", (tcpHeader->urg ? "URGENT|": ""));
            printf("%s", (tcpHeader->rst ? "RESET|" : ""));
            printf("\b\", ");
            printf("\"Sequence #\":0x%x, ", ntohl(tcpHeader->seq));
            printf("\"ACK\":0x%x, ", ntohl(tcpHeader->ack_seq));
            printf("\"Window\":0x%x, ", ntohs(tcpHeader->window));
            printf("\"Data Offset\":%d", 4 * tcpHeader->doff);
            printf("}\n");
            break;
     
        case IPPROTO_UDP:
            udpHeader = (struct udphdr*)packet;
            dataLength = dataLength - UDP_HEADER_SIZE;
            packet += UDP_HEADER_SIZE;
            printf("\"Protocol\":\"UDP\", ");
            printf("\"Source\":\"%s:%d\", ", srcIP, ntohs(udpHeader->source));
            printf("\"Destination\":\"%s:%d\", ", dstIP, ntohs(udpHeader->dest));
            printf("\"UDP Length\":\"%d\"", ntohs(udpHeader->len));
            printf("}\n");
            break;
     
        case IPPROTO_ICMP:
            icmpHeader = (struct icmphdr*)packet;
            memcpy(&id, (u_char*)icmpHeader+4, 2);
            memcpy(&seq, (u_char*)icmpHeader+6, 2);
            printf("\"Protocol\":\"ICMP\", ");
            printf("\"Source\":\"%s\", ", srcIP);
            printf("\"Destination\":\"%s\", ", dstIP);
            printf("\"Type\":\"%d\", ", icmpHeader->type);
            printf("\"Code\":\"%d\", ", icmpHeader->code);
            printf("\"ID\":\"%d\", ", ntohs(id));
            printf("\"Sequence\":\"%d\", ", ntohs(seq));
            printf("}\n");
            break;

        default:
            printf("\"Protocol\":0x%x", ipHeader->ip_p);
            break;
    }

    /* Navigate past the Transport layer to the payload: */
    if(dataLength > 0){
        printf("PAYLOAD (%d bytes):\n\t", dataLength);
        int k=0; 
        while( k < dataLength ){
            if( k%8 ==0 && k>0 )
                printf("    ");
            if( k%16 ==0 && k>0 )        
                printf("\n\t");
            printf("%02x ", packet[k]);
            k++;
        }        
    }
    printf("\n========================================================\n\n");
}
