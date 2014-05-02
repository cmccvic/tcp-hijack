#include "tcp-disrupt.h"

int tcpDisrupt(char *clientIP, char *serverIP, char *serverPort, char *networkInterface){
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                packetFilterString[256];
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

    clientIP = clientIP ? clientIP : DEFAULT_CLIENT_IP;
    serverIP = serverIP ? serverIP : DEFAULT_SERVER_IP;
    serverPort = serverPort ? serverPort : DEFAULT_SERVER_PORT;

    /* Initialize data: */
    memset(sniffArgs, 0, sizeof(spdcxSniffArgs));
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    memset(packetFilterString, 0, 256);

    snprintf(packetFilterString, 256, "tcp and port %s and host %s and host %s", serverPort, serverIP, clientIP);

    /* Determine the name of the network interface we are going to use: */
    if ( !networkInterface ){
        if ( (device = pcap_lookupdev(errbuf)) <= 0 ){
            fprintf(stderr, "[FAIL] pcap_lookupdev returned: \"%s\"\n", errbuf);
            free(sniffArgs);
            return 1;
        } else printf("[INFO] Found Hardware: %s\n", device);
    } else device = networkInterface;

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
    struct ip       *ipHeader;
    struct tcphdr   *tcpHeader;
    spdcxSniffArgs  *sniffArgs = (spdcxSniffArgs *)arg;;

    /* Navigate past the Data Link layer to the Network layer: */
    packet += sniffArgs->dataLinkOffset;
    ipHeader = (struct ip*)packet;
    dataLength = ntohs(ipHeader->ip_len) - (4 * ipHeader->ip_hl);
    strcpy(srcIP, inet_ntoa(ipHeader->ip_src));
    strcpy(dstIP, inet_ntoa(ipHeader->ip_dst));

    /* Navigate past the Network layer to the Transport layer: */
    packet += 4 * ipHeader->ip_hl;
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr*)packet;
            dataLength = dataLength - TCP_HEADER_SIZE;
            packet += TCP_HEADER_SIZE;
            break;
     
        default:
            break;
    }

    /* TODO: Figure out what the first twelve bits of telnet are*/
    packet += 12;
    dataLength -= 12;

    /* Navigate past the Transport layer to the payload: */
    if(dataLength > 0){
        printf("---------------------------------\n");
        printf("Src:%s\n", srcIP);
        printf("Src-Port: %d\n", ntohs(tcpHeader->source));
        printf("Dst:%s\n", dstIP); 
        printf("Dst-Port: %d\n", ntohs(tcpHeader->dest));
        printf("ACK:%zu\n", (size_t)ntohl(tcpHeader->ack_seq));  
        printf("Seq:%zu\n", (size_t)ntohl(tcpHeader->seq));   
        printf("Data:\n");
        printf("---------------------------------\n");

        int k=0;
        while( (dataLength>0) && (k<dataLength) ){
            if (isprint(packet[k]))
                printf("%c", packet[k]);
            else if (packet[k] == '\n')
                printf("\n");
            k++;
        }
        printf("\n");        
        printf("---------------------------------\n");
        printf("\n\n");        
    }
}
