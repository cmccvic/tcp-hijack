#include "tcp-disrupt.h"
#include "packet-send.h"
#include <stdlib.h>

int main(int argc, char const *argv[]) {
    int dstprt = 23;
    int srcprt = 1337;

    int packet_size = sizeof(struct tcphdr) + sizeof(struct iphdr);
    char *packet = malloc(packet_size);

    int sock, one = 1;

    //Address struct to sendto()
    struct sockaddr_in addr_in;

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
    addr_in.sin_port = htons(dstprt);
    addr_in.sin_addr.s_addr = inet_addr("192.168.1.1");

    fill_packet(
                    "127.0.0.1",       //srcIP
                    "192.168.1.112",   //dstIP
                    dstprt,            //dstPort
                    srcprt,            //srcPort
                    1,                 //syn
                    0,                 //ack
                    0,                 //seq
                    0,                 //ack_seq
                    0,                 //rst
                    "",                //data
                    packet,            //packet
                    packet_size        //packet_size
    );

    int ret = send_packet(sock, packet, addr_in);

    printf("sent %d bytes", ret);

    free(packet);

    return 0;
}