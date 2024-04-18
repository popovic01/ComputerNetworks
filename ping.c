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
unsigned char myip[4]= { 88,80,187,84 };
unsigned char netmask[4]= { 255,255,255,0 };
unsigned char gateway[4]= { 88,80,187,1 };
//another host in our network
unsigned char dest_ip[4]= { 88,80,187,83 };
unsigned char broadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};

#define ETH_MTU 1500

int s,i,t;
int sll_len,len;
struct sockaddr_ll sll;
unsigned char l2buf[ETH_MTU];

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
    unsigned char payload[1];
};

//calculating the checksum
unsigned short int checksum(void * ip, int len) {

    unsigned int tot = 0;
    unsigned short * p;
    int i;
    p = (unsigned short *) ip;

    for (i = 0; i < len / 2 ; i++) {
        tot = tot + htons(p[i]);
        if (tot & 0x10000) tot = (tot+1) & 0xFFFF;
    }

    if (i * 2 < len) {
        tot = tot + htons(p[i]) & 0xFF00;
        if (tot & 0x10000) tot = (tot+1) & 0xFFFF;
    }

    return  (0xFFFF-(unsigned short)tot);
}

//creating an ip packet
void forge_ip(struct ip_datagram * ip, unsigned short int payloadsize, unsigned char protocol, unsigned char * dest) {
    ip -> ver_ihl = 0x45; //ip version and header length
    ip -> tos = 0; //type of service
    ip -> totlen = htons(payloadsize + 20); //total length
    ip -> id = htons(0x1234); //we set id to 1234
    ip -> flags_offs = 0;
    ip -> ttl = 15; //time to live
    ip -> proto = protocol;
    ip -> checksum = htons(0);
    ip -> src = *(unsigned int *)myip;
    ip -> dst = *(unsigned int *)dest;
    ip -> checksum = htons(checksum(ip, 20));
}

struct icmp_packet {
    //Type: 8-echo request, 0-echo response
    unsigned char type;
    //Code: 0
    unsigned char code;
    //checksum, calculated using the same algorithm as for calculating checksum for an IP header
    unsigned short checksum;
    //ID - to uniquelly identify different ping requests
    unsigned short id;
    //Sequence number - could be used for tracking realibility (loss of the packages)
    //we increase it with every try to ping another node
    unsigned short seq;
    //data of the packet
    unsigned char payload[1];
};

void forge_icmp(struct icmp_packet * icmp, int payloadsize) {

    icmp -> type = 8;
    icmp -> code = 0;
    icmp -> checksum = htons(0);
    icmp -> id = htons(0xABCD); //we set id to ABCD
    icmp -> seq = htons(1);

    for (int i = 0; i < payloadsize; i++)
            icmp -> payload[i] = i % 0xFF;

    icmp -> checksum = htons(checksum(icmp, payloadsize+8)); //calling the same checksum method
}

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
    for (int i = 0; i < 6; i++) e -> dest[i] = dest[i];
    for (int i = 0; i < 6; i++) e -> src[i] = mymac[i];
    e -> type = htons(type);
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

int resolve_ip(unsigned char* target_ip, unsigned char* target_mac) {
    struct eth_frame * eth;
    struct arp_packet * arp;
    unsigned char l2buf[ETH_MTU];
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
    struct eth_frame *eth;
    struct ip_datagram *ip;
    struct icmp_packet *icmp;
    
    unsigned char dest_mac[6];
    s = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
            perror("Socket Failed");
            return 1;
    }

    eth = (struct eth_frame *) l2buf;
    ip = (struct ip_datagram *) eth->payload;
    icmp = (struct icmp_packet *) ip->payload;

    //create an ICMP packet
    //payload of ICMP is 20
    forge_icmp(icmp, 20);
    //create an IP packet
    //28 = 20 payload of ICMP + 8 header of ICMP
    //1 - protocol type value for ICMP
    forge_ip(ip, 28, 1, dest_ip);

    //we have to implement routing logic (routing table)
    /*if our IP address masked is equal of IP dest address masked, we send it to the IP dest address,
    otherwise we send it to the gateway*/

    //it is the same network as ours
    if (*(unsigned int *)myip & *(unsigned int *)netmask == *(unsigned int *)dest_ip & *(unsigned int *)netmask)
    {
        resolve_ip(dest_ip, dest_mac);
    }
    else //another network
    {
        resolve_ip(gateway, dest_mac);
    }

    printf("Dest MAC\n");
    print_buffer(dest_mac,6);

    //0x0800 is for IP protocol
    //create an ETHERNET packet
    forge_eth(eth, dest_mac, 0x0800);

    printf("Outgoing packet: ");

    //14-ETH header length, 20-IP header length, 8-ICMP header length, 20-ICMP payload length
    print_buffer(l2buf, 14+20+8+20);

    bzero(&sll,sizeof(struct sockaddr_ll));
    sll.sll_family=AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    sll_len=sizeof(struct sockaddr_ll);

    t = sendto(s, l2buf, 14+20+8+20, 0, (struct sockaddr *) &sll, sll_len);

    for (int i = 0 ; i < 100; i++) {
        len = recvfrom(s, l2buf, ETH_MTU, 0, (struct  sockaddr *) & sll, &sll_len);
        if (len == -1) {
            perror("recvfrom failed");
            return 1;
        }

        //check is it an IP packet
        if (eth->type == htons(0x0800)) {
            //check is it an ICMP packet
            if (ip->proto == 1) {
                //check is it an ICMP reply, an identifier of an ICMP reply and sequence of an ICMP reply
                if (icmp->Type == 0 && icmp->id == htons(0xABCD) && icmp->seq==htons(1)) {
                    printf("Echo reply\n");
                    print_buffer(l2buf, 14+20+8+20);
                    return 1;
                }
            }
        }
    }

    //vi ping.c
    //gcc ping.c -o ping
    //!gcc
    //./ping
    //cd /CN24
    //fg
}


