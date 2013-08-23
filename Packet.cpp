#include "Packet.h"


Packet::Packet(char* dest_ip,short dest_port,char* mode)
{
	string type = GetPacketType(mode);

	memset(packet,0,PKT_LEN);

	srcNetIP = inet_addr(getLocalIP());
	destNetIP = inet_addr(dest_ip);

	dest_net_addr.sin_family = AF_INET;
	dest_net_addr.sin_port = htons(dest_port);
	dest_net_addr.sin_addr.s_addr = destNetIP;

	ipHeader = (struct iphdr*)packet;
	ipHeader->ihl = 5;
	ipHeader->version = 4;
	ipHeader->tos = 0;
	ipHeader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	ipHeader->id = htons(55555);	//Id of this packet
	ipHeader->frag_off = 0;
	ipHeader->ttl = 255;

	ipHeader->check = 0;		//Set to 0 before calculating checksum
	ipHeader->saddr = srcNetIP;	//Spoof the source ip address
	ipHeader->daddr = destNetIP;
	ipHeader->check = GetChecksum ((unsigned short *) packet, ipHeader->tot_len >> 1);

	if(type == "TCP")
	{
		ipHeader->protocol = IPPROTO_TCP;

		tcpHeader = (struct tcphdr*)(packet + sizeof(struct ip));
		tcpHeader->source = htons (1216);
		tcpHeader->dest = htons (dest_port);
		tcpHeader->seq = 0;
		tcpHeader->ack_seq = 0;
		tcpHeader->doff = 5;		/* first and only tcp segment */

		tcpHeader->fin=0;
		tcpHeader->syn=0;
		tcpHeader->rst=0;
		tcpHeader->psh=0;
		tcpHeader->ack=0;
		tcpHeader->urg=0;
		if(strcmp(mode,"NULL") == 0)
		{
			tcpHeader->source = htons(NULL_PORT);
		}
		else if(strcmp(mode,"SYN") == 0)
		{
			tcpHeader->source = htons(SYN_PORT);
			tcpHeader->syn=1;
		}
		else if(strcmp(mode, "FIN") == 0)
		{
			tcpHeader->source = htons(FIN_PORT);
			tcpHeader->fin =1;
		}
		else if(strcmp(mode, "XMAS") == 0)
		{
			tcpHeader->source = htons(XMAS_PORT);
			tcpHeader->fin=1;
			tcpHeader->psh=1;
			tcpHeader->urg=1;
		}
		else if(strcmp(mode, "ACK") == 0)
		{
			tcpHeader->source = htons(ACK_PORT);
			tcpHeader->ack = 1;
		}

		tcpHeader->window = htons (PKT_LEN); //actual max is larger
		tcpHeader->check = 0;
		tcpHeader->urg_ptr = 0;

		psHeader.src_addr = srcNetIP;
		psHeader.dest_addr = destNetIP;
		psHeader.reserved = 0;
		psHeader.protocol = IPPROTO_TCP;
		psHeader.length = htons(20);

		memcpy(&psHeader.tcp , tcpHeader , sizeof (struct tcphdr));

		tcpHeader->check = GetChecksum( (unsigned short*) &psHeader , sizeof (struct pseudohdr));
	}
	else if(type == "UDP")
	{
		ipHeader->protocol = IPPROTO_UDP;

		udpHeader = (struct udphdr*)(packet + sizeof(struct ip));
		udpHeader->source = htons (1216);
		udpHeader->dest = htons (dest_port);
		udpHeader->len = htons(16);
		memcpy(&psHeader.udp , udpHeader , sizeof (struct udphdr));

		udpHeader->check = GetChecksum( (unsigned short*) &psHeader , sizeof (struct pseudohdr));

	}
	else if(type == "ICMP")
	{
		ipHeader->protocol = IPPROTO_ICMP;

		icmpHeader = (struct icmp*)(packet + sizeof(struct ip));
		icmpHeader->icmp_type = ICMP_ECHO;
		icmpHeader->icmp_code = 0;
		icmpHeader->icmp_id = htons (1000);
		icmpHeader->icmp_seq = htons (0);
		icmpHeader->icmp_cksum = 0;
		memcpy(&psHeader.ipc , icmpHeader , sizeof (struct icmp));

		icmpHeader->icmp_cksum = GetChecksum( (unsigned short*) &psHeader , sizeof (struct pseudohdr));
	}
	else
	{
		int protocol = 0;
		istringstream conv(type);
		if(!(conv>>protocol))
			protocol = 0;

		if(protocol >= 0 && protocol <= 255)
		{
			//tcpHeader->source = htons(1216);
			ipHeader->protocol = protocol;
		}

	}

	
}



string Packet::GetPacketType(char* mode)
{
	string sType = (string)mode;

	if(strcmp(mode,"6") == 0)
		sType = "TCP";
	else if(strcmp(mode,"17") == 0)
		sType = "UDP";
	else if(strcmp(mode,"1") == 0)
		sType = "ICMP";

	if(strcmp(mode,(char*)"SYN") == 0 || strcmp(mode,(char*)"ACK") == 0 ||
		strcmp(mode,(char*)"FIN") == 0 || strcmp(mode,(char*)"NULL") == 0 ||
		strcmp(mode,(char*)"XMAS") == 0)
		sType = "TCP";

	return sType;
}


unsigned short Packet::GetChecksum(unsigned short *ptr,int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1)
	{
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1)
	{
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}


char* Packet::getLocalIP()
{
	struct ifaddrs *addrs, *nextAddr;
	int iAddrFamily = 0;
	short len = 0;
	char* ip = (char*)malloc(NI_MAXHOST);

	getifaddrs(&addrs);

	for(nextAddr = addrs;nextAddr != NULL; nextAddr = nextAddr->ifa_next)
	{
		iAddrFamily = nextAddr->ifa_addr->sa_family;
		if(iAddrFamily == AF_INET || iAddrFamily == AF_INET6)
		{
			if(iAddrFamily == AF_INET)
				len = sizeof(struct sockaddr_in);
			else if(iAddrFamily == AF_INET6)
				len = sizeof(struct sockaddr_in6);

			getnameinfo(nextAddr->ifa_addr,len,ip,NI_MAXHOST,NULL, 0, NI_NUMERICHOST);

			if(strcmp(ip,"127.0.0.1") != 0)
				return ip;
	
		}
	}
	return (char*)"NULL";
}


Packet::~Packet() {
	// TODO Auto-generated destructor stub
}

