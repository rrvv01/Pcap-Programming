#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>



/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};


/* IP header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};


/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};



void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
    

    // MAC주소 출력
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    

    // IP주소 출력
    printf("Source ip: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("Destination ip: %s\n", inet_ntoa(ip->iph_destip)); 


    //TCP 포트 출력
    printf("Source port: %u\n", ntohs(tcp->tcp_sport));
    printf("Destination port: %u\n", ntohs(tcp->tcp_dport));

    printf("\n");

}


int main() {
    pcap_t *handle;
    char *dev = "eth0"; 
    char errbuf[PCAP_ERRBUF_SIZE];

		// 네트워크 디바이스 open
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "디바이스 오픈 안됨. %s: %s\n", dev, errbuf);
        return 1;
    }
		
		// 패킷 캡쳐 시작
    pcap_loop(handle, 0, packet_capture, NULL);
		
		// pcap 닫기
    pcap_close(handle);

    return 0;
}
