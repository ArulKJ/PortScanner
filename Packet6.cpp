/*
 * Packet6.cpp
 *
 *  Created on: Oct 30, 2012
 *      Author: arul
 */

#include "Packet6.h"

Packet6::Packet6() {
	// TODO Auto-generated constructor stub

}


Packet6::Packet6(char* dest_ip,short dest_port,char* mode)
{
	char* srcIP;
	char* dstIP;

	strcpy(srcIP,"2001:18e8:2:10f4:5054:ff:fefe:23e4");
	strcpy(dstIP,"ipv6.google.com");

	dest_net_addr.sin_family = AF_INET6;
	dest_net_addr.sin_port = htons(dest_port);
	dest_net_addr.sin_addr.s_addr = inet_addr(dstIP);

	memset(packet,0,PKT_LEN);

	ipHeader = (struct ip6_hdr*)packet;

	ipHeader->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  	ipHeader->ip6_plen = htons (20);

  	ipHeader->ip6_nxt = IPPROTO_TCP;

  	ipHeader->ip6_hops = 255;

    inet_pton (AF_INET6, srcIP, &ipHeader->ip6_src);
    inet_pton (AF_INET6, dstIP, &ipHeader->ip6_dst);


	tcpHeader = (struct tcphdr*)(packet + sizeof(struct ip));
	tcpHeader->source = htons (1216);
	tcpHeader->dest = htons (dest_port);
	tcpHeader->seq = 0;
	tcpHeader->ack_seq = 0;
	tcpHeader->doff = 5;		/* first and only tcp segment */

	tcpHeader->fin=0;
	tcpHeader->syn=1;
	tcpHeader->rst=0;
	tcpHeader->psh=0;
	tcpHeader->ack=0;
	tcpHeader->urg=0;

	int sockfd = socket (AF_INET6, SOCK_RAW, IPPROTO_TCP);
	int retval = sendto(sockfd,packet,74,0,(struct sockaddr*)&dest_net_addr,sizeof(dest_net_addr));

	cout<<"IP6 Send :"<<retval<<endl;

}


Packet6::~Packet6() {
	// TODO Auto-generated destructor stub
}


