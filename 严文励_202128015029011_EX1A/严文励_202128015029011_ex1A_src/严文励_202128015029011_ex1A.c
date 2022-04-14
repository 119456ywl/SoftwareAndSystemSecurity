#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define BUFSIZE 65536
#define MAX_LOOP_COUNT 1000
typedef unsigned long ULONG;

int loopcount = 0;

void callback(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* size);
void dealwithTCP(const unsigned char* size, int iplen, struct ip* ip);

void print_payload(int n,const char* buff){
	int i=0,j=0;
	for(i=0;i<n;i++){
		if(i!=0&&i%16==0){
			printf("  ");
			for(j=i-16;j<i;j++){
				if(buff[j]>=32&&buff[j]<=128)
					printf("%c",buff[j]);
				else printf(".");
			}
			printf("\n");
		}
		if (i%16==0) printf ("%04x ",i);
		printf("%02x",buff[i]);
		if(i==n-1){
			for(j=0;j<15-i%16;j++) printf(" ");
			printf(" ");
			for(j=i-i%16;j<=i;j++){
				if(buff[j]>=32&&buff[j]<127)
					printf("%c",buff[j]);
				else printf(".");
			}
		}
	}
}
int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    char* devname;
    bpf_u_int32 devnet, devmask;
    
    pcap_t* handle;
    struct bpf_program fp;
    char fpstr[BUFSIZE];
    
    struct in_addr addr;
    
    char errBuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errBuf) == -1) {
        printf("error1: %s\n",errBuf);
        exit(1);
    }
    for (dev = alldevs; dev; dev = dev->next) {
        printf("device: %s\n", dev->name);
    }
    devname = alldevs->name;
    if (pcap_lookupnet(devname, &devnet, &devmask, errBuf) == -1) {
        printf("error2: %s\n",errBuf);
        exit(1);
    }
    addr.s_addr = devnet;
    printf("Net: %s\n", inet_ntoa(addr));
    addr.s_addr = devmask;
    printf("Mask: %s\n", inet_ntoa(addr));
    
    handle = pcap_open_live(devname, BUFSIZ, 1, 1000, errBuf);
    if (handle == NULL) {
        printf("error3: %s\n",errBuf);
        exit(1);
    }
    if (pcap_compile(handle, &fp, fpstr, 1, devmask) == -1) {
        printf("error4: %s\n",errBuf);
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("error5: %s\n",errBuf);
        exit(1);
    }
    if (pcap_loop(handle, MAX_LOOP_COUNT, callback, NULL) == -1) {
        printf("error6: loop failed\n");
        exit(1);
    }
    pcap_freecode(&fp);
	pcap_close(handle);
    return 0;
}

void callback(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* size){
    int iplen;
	struct ip* ip = (struct ip*)(size + 14);
    iplen = ip->ip_hl*4;
    printf("the %d th package\n", ++loopcount);
	printf("length: %d\nsrc: %s\ndst: %s\n", iplen, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
	switch(ip->ip_p){
		case IPPROTO_TCP: {
            dealwithTCP(size, iplen, ip);
            break;
        }
		case IPPROTO_UDP: {
            printf("Protocol UDP\n\n");
            break;
        }
		case IPPROTO_ICMP: {
            printf("Protocol ICMP\n\n");
            break;
        }
		case IPPROTO_IP: {
            printf("Protocol IP\n\n");
            break;
        }
        /*case IPPROTO_TLS: {
            printf("Protocol TLS\n\n");
            break;
        }*/
		default: {
            printf("Other Protocol\n\n");
			return;
        }
	}
}

void dealwithTCP(const unsigned char* size, int iplen, struct ip* ip) {
    struct tcphdr* tcp;
    const char* tcpflow;
    int flowsize;
    int i, j;
    printf("Protocol TCP\n");
    tcp = (struct tcphdr*)(size + 14 + iplen);
    flowsize = ntohs(ip->ip_len) - iplen - 4*tcp->doff;
    if (flowsize <= 0) {
        printf("Empty TCP Flow\n\n");
        return;
    }
    tcpflow = (unsigned char*)tcp;
    
    for (i = 1; i <= flowsize; ++i) {
        if (i % 16 == 1) {
            printf("%04x ", i-1);
            for (j = i; j < i + 16 && j <= flowsize; ++j) {
                if (tcpflow[j] >= 32 && tcpflow[j] <= 128)
                    printf("%c",tcpflow[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
    printf("Total %d chars\n\n", flowsize);
    return;
}
