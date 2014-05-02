#include "tcp-disrupt.h"

void send_packet(int socket_fd, char *packet, struct sockaddr_in addr_in) {
    int bytes;
    struct iphdr *ipHdr = (struct iphdr *) packet;

    if((bytes = sendto(socket_fd, ipHdr, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0) {
        perror("Error on sendto()");
    }
    else {
        printf("\nSuccess! Sent %d bytes.\n", bytes);
    }
}

void fill_packet(   char *srcIP,
                    char *dstIP,
                    u_int16_t dstPort,
                    u_int16_t srcPort,
                    u_int32_t syn,
                    u_int16_t ack,
                    u_int32_t seq,
                    u_int32_t ack_seq,
                    const char * data,
                    char *packet,
                    uint32_t packet_size) {

    struct iphdr *ipHdr;
    struct tcphdr *tcpHdr;
    char *pseudo_packet;
    struct pseudoTCPPacket pTCPPacket;

    memset(packet, 0 ,packet_size);
    ipHdr = (struct iphdr*) packet;
    tcpHdr = (struct tcphdr*) (packet + sizeof(struct iphdr));
    memcpy((char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr)), data, strlen(data));

    //IP header
    ipHdr->ihl = 5;
    ipHdr->version = 4;
    ipHdr->tos = 0;
    ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    ipHdr->id = htons(54321);
    ipHdr->frag_off = 0;
    ipHdr->ttl = 0xFF;
    ipHdr->protocol = IPPROTO_TCP;
    ipHdr->saddr = inet_addr(srcIP);
    ipHdr->daddr = inet_addr(dstIP);
    ipHdr->check = csum((unsigned short *) packet, ipHdr->tot_len);

    //TCP header
    tcpHdr->source = htons(srcPort);
    tcpHdr->dest = htons(dstPort);
    tcpHdr->seq = htonl(seq);
    tcpHdr->ack_seq = htonl(ack_seq);
    tcpHdr->res1 = 0;
    tcpHdr->doff = 5;
    tcpHdr->fin = 0;
    tcpHdr->syn = syn;
    tcpHdr->rst = 0;
    tcpHdr->psh = 0;
    tcpHdr->ack = ack;
    tcpHdr->urg = 0;
    tcpHdr->res2 = 0;
    tcpHdr->window = htons(43690);
    tcpHdr->urg_ptr = 0;

    printf("seq: %u\n", tcpHdr->seq);
    printf("ack_seq: %u\n", tcpHdr->ack_seq);

    //calculate the checksum for the TCP header
    pTCPPacket.srcAddr = inet_addr(srcIP);
    pTCPPacket.dstAddr = inet_addr(dstIP);
    pTCPPacket.zero = 0;
    pTCPPacket.protocol = IPPROTO_TCP;
    pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data));

    pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));

    memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));
    memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + strlen(data));

    tcpHdr->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) + 
          sizeof(struct tcphdr) +  strlen(data))));

    free(pseudo_packet);

    int i;
    printf("\n");
    for (i = 0; i < packet_size; ++i) {

        if((i % 4) == 0) {
            printf("\n");
        }

        printf("%d", (0x01 & *(packet + i) >> 7));
        printf("%d", (0x01 & *(packet + i) >> 6));
        printf("%d", (0x01 & *(packet + i) >> 5));
        printf("%d", (0x01 & *(packet + i) >> 4));
        printf(" ");
        printf("%d", (0x01 & *(packet + i) >> 3));
        printf("%d", (0x01 & *(packet + i) >> 2));
        printf("%d", (0x01 & *(packet + i) >> 1));
        printf("%d", (0x01 & *(packet + i) >> 0));
        printf(" ");

        if(i == 19) {
            printf("\n------------------TCP------------------");
        } else if(i == (20+19)) {
            printf("\n------------------DATA-----------------");
        }
    }
}


void gen_packet(  char *srcIP,
                  char *dstIP,
                  u_int16_t dstPort,
                  u_int16_t srcPort,
                  u_int32_t syn,
                  u_int16_t ack,
                  u_int32_t seq,
                  u_int32_t ack_seq,
                  char data,
                  char *packet,
                  uint32_t packet_size) {

    struct iphdr *ipHdr;
    struct tcphdr *tcpHdr;
    char *pseudo_packet;
    struct pseudoTCPPacket pTCPPacket;

    memset(packet, 0, packet_size);
    ipHdr = (struct iphdr *) packet;
    tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
    char *packet_data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
    *packet_data = data;
    //strcpy(packet_data, data);

    //Populate ipHdr
    ipHdr->ihl = 5;                                                      //5 x 32-bit words in the header
    ipHdr->version = 4;                                                  // ipv4
    ipHdr->tos = 0;                                                      //tos = [0:5] DSCP + [5:7] Not used, low delay
    ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + 1;   //strlen(packet_data);                                                          //total lenght of packet. len(data) = 0
    ipHdr->id = htons(54321);                                            // 0x00: 16 bit id
    ipHdr->frag_off = 0x00;                                              //16 bit field = [0:2] flags + [3:15] offset = 0x0
    ipHdr->ttl = 0xFF;                                                   //16 bit time to live (or maximal number of hops)
    ipHdr->protocol = IPPROTO_TCP;                                       //TCP protocol
    ipHdr->check = 0;                                                    //16 bit checksum of IP header. Can't calculate at this point
    ipHdr->saddr = inet_addr(srcIP);                                     //32 bit format of source address
    ipHdr->daddr = inet_addr(dstIP);                                     //32 bit format of source address

    //Now we can calculate the check sum for the IP header check field
    ipHdr->check = csum((unsigned short *) packet, ipHdr->tot_len); 

    //Populate tcpHdr
    tcpHdr->source = htons(srcPort);        //16 bit in nbp format of source port
    tcpHdr->dest = htons(dstPort);          //16 bit in nbp format of destination port
    tcpHdr->seq = htonl(seq);               //seq: 32 bit sequence number, initially set to zero
    tcpHdr->ack_seq = htonl(ack_seq);       //ack_seq: 32 bit ack sequence number, depends whether ACK is set or not
    tcpHdr->doff = 5;                       //4 bits: 5 x 32-bit words on tcp header
    tcpHdr->res1 = 0;                       //4 bits: Not used
    tcpHdr->urg = 0;                        //Urgent flag
    tcpHdr->ack = ack;                      //Acknownledge
    tcpHdr->psh = 0;                        //Push data immediately
    tcpHdr->rst = 0;                        //RST flag
    tcpHdr->syn = syn;                      //SYN flag
    tcpHdr->fin = 0;                        //Terminates the connection
    tcpHdr->window = htons(43690);          //0xFFFF: 16 bit max number of databytes 
    tcpHdr->check = 0;                      //16 bit check sum. Can't calculate at this point
    tcpHdr->urg_ptr = 0;                    //16 bit indicate the urgent data. Only if URG flag is set

    /* TODO: Check the Linux -> BSD conversion for these fields: */
    //  tcpHdr->cwr = 0; //Congestion control mechanism
    //  tcpHdr->ece = 0; //Congestion control mechanism

    printf("seq: %u\n", tcpHdr->seq);
    printf("ack_seq: %u\n", tcpHdr->ack_seq);

    //Now we can calculate the checksum for the TCP header
    pTCPPacket.srcAddr = inet_addr(srcIP); //32 bit format of source address
    pTCPPacket.dstAddr = inet_addr(dstIP); //32 bit format of source address
    pTCPPacket.zero = 0; //8 bit always zero
    pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
    pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(packet_data)); // 16 bit length of TCP header

    //Populate the pseudo packet
    pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(packet_data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(packet_data));

    //Copy pseudo header
    memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));
    memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + strlen(packet_data));

    tcpHdr->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) + 
          sizeof(struct tcphdr) +  strlen(packet_data))));

    free(pseudo_packet);

    int i;
    printf("\n");
    for (i = 0; i < packet_size; ++i) {

        if((i % 4) == 0) {
            printf("\n");
        }

        printf("%d", (0x01 & *(packet + i) >> 7));
        printf("%d", (0x01 & *(packet + i) >> 6));
        printf("%d", (0x01 & *(packet + i) >> 5));
        printf("%d", (0x01 & *(packet + i) >> 4));
        printf(" ");
        printf("%d", (0x01 & *(packet + i) >> 3));
        printf("%d", (0x01 & *(packet + i) >> 2));
        printf("%d", (0x01 & *(packet + i) >> 1));
        printf("%d", (0x01 & *(packet + i) >> 0));
        printf(" ");

        if(i == 19) {
            printf("\n------------------TCP------------------");
        } else if(i == (20+19)) {
            printf("\n------------------DATA-----------------");
        }
    }
}


unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}