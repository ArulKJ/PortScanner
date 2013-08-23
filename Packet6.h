/*
 * Packet6.h
 *
 *  Created on: Oct 30, 2012
 *      Author: arul
 */

#include "PortScanner.h"
#include <netinet/ip6.h>
#include <netinet/tcp.h>      // struct tcphdr


#ifndef PACKET6_H_
#define PACKET6_H_

class Packet6
{
private:
	char packet[PKT_LEN];
	int srcNetIP,destNetIP;
	struct ip6_hdr* ipHeader;
	struct tcphdr* tcpHeader;
	struct udphdr* udpHeader;
	struct icmp* icmpHeader;
	struct pseudohdr psHeader;
	struct sockaddr_in dest_net_addr;


public:
	Packet6();
	Packet6(char* dest_ip,short dest_port,char* mode);
	virtual ~Packet6();
};

#endif /* PACKET6_H_ */
