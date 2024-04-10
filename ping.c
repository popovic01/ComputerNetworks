#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <net/if.h>

//our mac - check in cmd using command 'ipconfig /all'
//my mac address is 90-65-84-D0-AB-2F
unsigned char mymac[6] = { 0xf2,0x3c,0x91,0xdb,0xc2,0x98 };
//server's IP address, 4 because it is 4 bytes long
unsigned char myip[4]= { 88,80,187,84};
//another host in our network
unsigned char dest_ip[4]= { 88,80,187,83};
unsigned char broadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};

#define ETH_MTU 1500

struct eth_frame {
    //dest MAC address
    unsigned char dest[6];
    //source MAC address
    unsigned char src[6];
    //type of the ULP encapsulated in the frame
    unsigned short type;
    //pointer to the first element of the array
    unsigned char payload[1];
};

struct ip_datagram {
    //IP version and header length
    unsigned char ver_ihl;
    //Type of Service
    unsigned char tos;
    //Total Length of a packet
    unsigned short totlen;
    //ID for fragmentation
    unsigned short id;
    //flags and offset for fragmentation
    unsigned short flag_offs;
    //Time to live
    unsigned char ttl;
    //type of the ULP encapsulated in the datagram
    unsigned char proto;
    //checksum, calculated only for an IP header
    unsigned short checksum;
    //source IP address
    unsigned int src;
    //destination IP address
    unsigned int dst;
};

struct icmp_packet {
    //Type: 8-request, 0-response
    unsigned char type;
    //Code: 0
    unsigned char code;
    //checksum, calculated using the same algorithm as for calculating checksum for an IP header
    unsigned short checksum;
    //ID - to uniquelly identify different ping requests
    unsigned short id;
    //Sequence number - could be used for tracking realibility (loss of the packages)
    unsigned short seq;
    //data of the packet
    unsigned char payload[1];
};

struct arp_packet {
    //type of layer 2 protocol
    unsigned short htype;
    //type of layer 3 protocol
    unsigned short ptype;
    //length of layer 2 protocol address
    unsigned char hsize;
    //length of layer 3 protocol address
    unsigned char psize;
    //operation: 1-request, 2-response
    unsigned short op;
    //source hardware address
    unsigned char hsrc[6];
    //source protocol address
    unsigned char psrc[4];
    //destination hardware address
    unsigned char hdst[6];
    //destination protocol address
    unsigned char pdst[4];
};

void forge_eth (struct eth_frame * e, unsigned char * dest, unsigned short type)
{
    for (int i = 0; i < 6; i++) e->dest[i] = dest[i];
    for (int i = 0; i < 6; i++) e->src[i] = mymac[i];
    e->type = htons(type);
}

void forge_arp_req(struct arp_packet * a, unsigned char * targetip) {
    a->htype = htons (1);
    a->ptype = htons (0x0800);
    a->hsize = 6;
    a->psize = 4;
    a->op = htons(1);
    for (int i = 0; i < 6; i++) a->hsrc[i] = mymac[i];
    for (int i = 0; i < 4; i++) a->psrc[i] = myip[i];

    for (int i = 0; i < 6; i++) a->hdst[i] = 0;
    for (int i = 0; i < 4; i++) a->pdst[i] = targetip[i];
}

void print_buffer(unsigned char * b, int s) {
	for (int i=0; i<s; i++) {
	        if (!(i%4))
			    printf("\n");
		printf("%.2X (%.3d) ", b[i], b[i]);
		}
	printf("\n");
}

int s,i,t;
int sll_len,len;
struct sockaddr_ll sll;
unsigned char l2buf[ETH_MTU];

int resolve_ip(unsigned char* target_ip, unsigned char* target_mac) {
    struct eth_frame * eth;
    struct arp_packet * arp;
    bzero(&sll,sizeof(struct sockaddr_ll));
    sll.sll_family=AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    sll_len=sizeof(struct sockaddr_ll);

    eth = (struct eth_frame *) l2buf;
    arp = (struct arp_packet *) eth->payload;
    forge_eth(eth,broadcast,0x0806);
    forge_arp_req(arp,target_ip);

    print_buffer(l2buf,6+6+2+sizeof(struct arp_packet));
    t = sendto(s, l2buf,14+sizeof(struct arp_packet), 0, (struct sockaddr *) &sll, sll_len);
    printf("%d  bytes sent\n",t);

    for(int i =0 ; i< 100; i++) {
        len = recvfrom(s, l2buf, ETH_MTU, 0, (struct  sockaddr *) & sll, &sll_len);
        if (len == -1 ) {
            perror("recvfrom failed");
            return 1;
        }
        //result of the memcmp method is 0 if the two values are the same
        //the last parameter of the memcmp method is length in bytes
        if (eth->type == htons(0x0806) && !memcmp(eth->dest,mymac, 6))
            if (arp->op == htons(2) && !memcmp(target_ip,arp->psrc, 4)) {
                print_buffer(l2buf, 6+6+2+sizeof(struct arp_packet));
                //we copy arp->hsrc to target_mac - that is the mac address that has been resolved
                memcpy(target_mac, arp->hsrc, 6);
                return 0; //success
            }
        }
    return 1; //failed
}

int main() {
    unsigned char dest_mac[6];
    s = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if ( s == -1) {
            perror("Socket Failed");
            return 1;
        }

    resolve_ip(dest_ip,dest_mac);
    printf("Dest MAC\n");
    print_buffer(dest_mac,6);
}


