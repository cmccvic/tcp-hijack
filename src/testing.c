#include "tcphijack.h"
//Data to be sent (appended at the end of the TCP header)
//#define DATA "datastring"
#define DATA ""

//Debug function: dump 'index' bytes beginning at 'buffer'
void hexdump(unsigned char *buffer, unsigned long index) {
  unsigned long i;
  printf("hexdump on address %p:\n", buffer);
  for (i=0;i<index;i++)
  {
    printf("%02x ",buffer[i]);
  }
  printf("\n");
}

//Calculate the TCP header checksum of a string (as specified in rfc793)
//Function from http://www.binarytides.com/raw-sockets-c-code-on-linux/
unsigned short csum(unsigned short *ptr,int nbytes);

void send_packet(int socket_fd, char *packet, struct sockaddr_in addr_in);

void gen_packet(  char *srcIP,
                  char *dstIP,
                  int dstPort,
                  int srcPort,
                  int syn,
                  int ack,
                  int seq,
                  int ack_seq,
                  char *data,
                  char *packet,
                  int packet_size);


//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

int main(int argc, char **argv) {
  int sock, one = 1;

  //Setup
  char *srcIP = "127.0.0.1";
  char *dstIP = "127.0.0.1";
  int dstPort = 1337;
  int srcPort = 1338;
  int packet_size = 512;

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
                1, //syn
                0, //ack
                0, //seq
                0, //syn_ack
                "", //data
                packet,
                packet_size);

    send_packet(sock, packet, addr_in);
    

    break;
  }
  
  return 0;
}

void send_packet(int socket_fd, char *packet, struct sockaddr_in addr_in) {
  int bytes;
  struct iphdr *ipHdr = (struct iphdr *) packet;

  if((bytes = sendto(socket_fd, ipHdr, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0) {
    perror("Error on sendto()");
  }
  else {
    printf("Success! Sent %d bytes.\n", bytes);
  }
}


void gen_packet(  char *srcIP,
                  char *dstIP,
                  int dstPort,
                  int srcPort,
                  int syn,
                  int ack,
                  int seq,
                  int ack_seq,
                  char *data,
                  char *packet,
                  int packet_size) {

  struct iphdr *ipHdr;
  struct tcphdr *tcpHdr;
  char *pseudo_packet;
  struct pseudoTCPPacket pTCPPacket;

  memset(packet, 0, packet_size);
  ipHdr = (struct iphdr *) packet;
  tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
  data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
  //strcpy(data, DATA);

  //Populate ipHdr
  ipHdr->ihl = 5; //5 x 32-bit words in the header
  ipHdr->version = 4; // ipv4
  ipHdr->tos = 0;// //tos = [0:5] DSCP + [5:7] Not used, low delay
  ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data); //total lenght of packet. len(data) = 0
  ipHdr->id = htons(54321); // 0x00; //16 bit id
  ipHdr->frag_off = 0x00; //16 bit field = [0:2] flags + [3:15] offset = 0x0
  ipHdr->ttl = 0xFF; //16 bit time to live (or maximal number of hops)
  ipHdr->protocol = IPPROTO_TCP; //TCP protocol
  ipHdr->check = 0; //16 bit checksum of IP header. Can't calculate at this point
  ipHdr->saddr = inet_addr(srcIP); //32 bit format of source address
  ipHdr->daddr = inet_addr(dstIP); //32 bit format of source address

  //Now we can calculate the check sum for the IP header check field
  ipHdr->check = csum((unsigned short *) packet, ipHdr->tot_len); 

  //Populate tcpHdr
  tcpHdr->source = htons(srcPort); //16 bit in nbp format of source port
  tcpHdr->dest = htons(dstPort); //16 bit in nbp format of destination port
  tcpHdr->seq = seq; //32 bit sequence number, initially set to zero
  tcpHdr->ack_seq = ack_seq; //32 bit ack sequence number, depends whether ACK is set or not
  tcpHdr->doff = 5; //4 bits: 5 x 32-bit words on tcp header
  tcpHdr->res1 = 0; //4 bits: Not used
  tcpHdr->cwr = 0; //Congestion control mechanism
  tcpHdr->ece = 0; //Congestion control mechanism
  tcpHdr->urg = 0; //Urgent flag
  tcpHdr->ack = ack; //Acknownledge
  tcpHdr->psh = 0; //Push data immediately
  tcpHdr->rst = 0; //RST flag
  tcpHdr->syn = syn; //SYN flag
  tcpHdr->fin = 0; //Terminates the connection
  tcpHdr->window = htons(43690);//0xFFFF; //16 bit max number of databytes 
  tcpHdr->check = 0; //16 bit check sum. Can't calculate at this point
  tcpHdr->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set

  //Now we can calculate the checksum for the TCP header
  pTCPPacket.srcAddr = inet_addr(srcIP); //32 bit format of source address
  pTCPPacket.dstAddr = inet_addr(dstIP); //32 bit format of source address
  pTCPPacket.zero = 0; //8 bit always zero
  pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
  pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data)); // 16 bit length of TCP header

  //Populate the pseudo packet
  pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
  memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));

  //Copy pseudo header
  memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));
  memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + strlen(data));

  tcpHdr->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) + 
          sizeof(struct tcphdr) +  strlen(data))));

  free(pseudo_packet);
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