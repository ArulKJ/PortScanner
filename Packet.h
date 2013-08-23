#include "PortScanner.h"


#ifndef PACKET_H_
#define PACKET_H_

class Packet
{

private:

	char packet[PKT_LEN];
	int srcNetIP,destNetIP;
	struct iphdr* ipHeader;
	struct tcphdr* tcpHeader;
	struct udphdr* udpHeader;
	struct icmp* icmpHeader;
	struct pseudohdr psHeader;
	struct sockaddr_in dest_net_addr;

	Packet()
	{	}

public:

	Packet(char* dest_ip,short dest_port,char* mode);
	unsigned short GetChecksum(unsigned short *ptr,int nbytes);
	string GetPacketType(char* mode);
	virtual ~Packet();

	char* getLocalIP();

	struct sockaddr_in getDestNetAddr() const {
		return dest_net_addr;
	}

	struct iphdr* getIpHeader() const {
		return ipHeader;
	}

	char* getPacket() {
		return packet;
	}

	int getSrcNetIp() const {
		return srcNetIP;
	}

	struct tcphdr* getTcpHeader() const {
		return tcpHeader;
	}
};

#endif /* PACKET_H_ */
