#include "PortScanner.h"
#include "Packet.h"
#include "PortOutput.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


#ifndef SCANNER_H_
#define SCANNER_H_

class Scanner
{
private:
	Stack* portStack;
	bool* modes;
	char* dest_ip;
	int* prtcls;
	int prtclsLen;
	int ipver;
	int num_threads;
	PortOutput arrOP[1024];
	int portOPLen; 
	int sockfd;
	pthread_t scanThrd;
	pthread_mutex_t lock;
	string ipOutput; 
	char* sSinffingDevice;
	pcap_t *pDescr;
	pcap_t *pLBDescr;
	pthread_t recvThrd;
	pthread_t recvLBThrd;
	bool bContinueSniffing;
	int arrProtocolOP[256];
	Scanner()
	{	}

public:
	Scanner(PortScnParam* params, char* ip);
	int GetSocket();
	void Begin();
	static void* Scan(void* mode);
	bool CheckForResponses(string ip, int port, char* mode);
	void SendPacket(int port,char* mode);
	void PrintScanDetails(); 
	virtual ~Scanner();
	
	static void* PreparePacketScanner(void* obj); 
	static void* PrepareLoopBackPS(void* obj);
	friend void ProcessPacket(u_char *arg,const struct pcap_pkthdr* pkthdr, const u_char* packet);


	int* getPrtcls() const {
		return prtcls;
	}

	void setPrtcls(int* prtcls) {
		this->prtcls = prtcls;
	}

	int getPrtclsLen() const {
		return prtclsLen;
	}

	void setPrtclsLen(int prtclsLen) {
		this->prtclsLen = prtclsLen;
	}

	char* getDestIp()  {
		return dest_ip;
	}

	void setDestIp(char* destIp) {
		dest_ip = destIp;
	}

	const bool* getModes() const {
		return modes;
	}

	int getNumThreads() const {
		return num_threads;
	}

	void setNumThreads(int numThreads) {
		num_threads = numThreads;
	}

	Stack* getPortStack() const {
		return portStack;
	}

	void setPortStack(Stack* portStack) {
		this->portStack = portStack;
	}

};

#endif /* SCANNER_H_ */
