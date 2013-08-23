#include "IPPrefix.h"

IPPrefix::IPPrefix() {

}


IPPrefix::IPPrefix(string sIP, int netBits)
{

	char* ip;
	memcpy(&ip,&sIP,sizeof(sIP));
	long int givenIP = htonl(inet_addr(ip));
	
	int hostBits = 32 - netBits;
	long int netMask = htonl(inet_addr("255.255.255.255"));
	netMask = netMask << hostBits;

	currentIP = givenIP & netMask;
	totalHosts = pow(2,hostBits) - 2;
	ipIndex = 0;

}



char* IPPrefix::GetNextIP()
{
	if(ipIndex<totalHosts)
	{
		struct in_addr addr;

		currentIP += 1;
		addr.s_addr = ntohl(currentIP);
		ipIndex++;
		return inet_ntoa(addr);
	}
	else
		return (char*)"EMPTY";

	return (char*)"EMPTY";
}



IPPrefix::~IPPrefix() {
}

