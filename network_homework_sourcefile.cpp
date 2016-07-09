#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h> // To use inet_ntoa() 
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ether.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0


struct ip *iph; //ip header struct

struct tcphdr *tcph; //tcp header struct

// 패킷을 받아들일경우 이 함수를 호출한다.  
// packet 가 받아들인 패킷이다.
void receive_packet(u_char *useless, const struct pcap_pkthdr *pkthdr, 
                const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;    
    int chcnt =0;
    int length=pkthdr->len;
 
    ep = (struct ether_header *)packet; //packet 가 받아들인 패킷이다.
						
					// 이더넷 헤더를 가져온다.

    printf("Src Ehtnet: %s\n",ether_ntoa((struct ether_addr *)ep->ether_shost));
    printf("Dest Ehtnet: %s\n",ether_ntoa((struct ether_addr *)ep->ether_dhost));
 
    packet += sizeof(struct ether_header);    // IP 헤더를 가져오기 위해서 
    					      // 이더넷 헤더 크기만큼 Plus offset 

    ether_type = ntohs(ep->ether_type); // 프로토콜 타입을 알아낸다. 

    if (ether_type == ETHERTYPE_IP) // 만약 IP 패킷이라면
    {
        // IP 헤더에서 데이타 정보를 출력한다.  
        iph = (struct ip *)packet;

        printf("Src IP Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst IP Address : %s\n", inet_ntoa(iph->ip_dst));

        // 만약 TCP 데이타 라면 TCP 정보를 출력한다. 
        if (iph->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
        }
    }
    printf("\n\n");
}    

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;
   // char filter_exp[] = "port 80";

    struct bpf_program fp; //필터링 룰에 의해 결정될 구조체 

    pcap_t *pcd;  // packet capture descriptor

    // 사용중인 디바이스 이름을 얻어온다. 
    dev = pcap_lookupdev(errbuf);

    printf("DEV : %s\n", dev);

    // 디바이스 이름에 대한 네트웍/마스크 정보를 얻어온다. 
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    net_addr.s_addr = netp;

    pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);

    // 컴파일 옵션을 준다.
    if (pcap_compile(pcd, &fp,argv[2], 0, netp) == -1)
    {
        printf("compile error\n");    
        exit(1);
    }

    // 컴파일 옵션대로 패킷필터 룰을 세팅한다. 
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);    
    }

    pcap_loop(pcd, atoi(argv[1]), receive_packet, NULL); // Callback when packet received
}

