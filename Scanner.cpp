#include "Scanner.h"

Scanner::Scanner(PortScnParam* params, char* ip)
{
	
	dest_ip = ip;
	portStack = new Stack(params->GetPortList(),params->GetPortListLength());
	portOPLen = params->GetPortListLength();
	int* portList = params->GetPortList();
	modes = params->GetScanValues();
	
	num_threads = params->GetNoOfThreads();
	sockfd = GetSocket();
	prtcls = params->GetProtocolRangeList();
	prtclsLen = params->GetProtocolRangeListLength();
	//
	
	bool bUDPPresent = false;
	for (int idx=1;idx<256;idx++) {
		arrProtocolOP[idx]=NOT_USED;
		for (int idx1=0;idx1<prtclsLen;idx1++) {
			if(idx==prtcls[idx1]) {
				arrProtocolOP[idx]=NO_ANSWER_YET;
				if(idx == 17 && modes[5] == true) {
					bUDPPresent = true;
				}
			}
			
		}
	}
	
	for (int idx=0;idx<portOPLen;idx++) {
			arrOP[idx] = PortOutput(portList[idx],modes);
			if(bUDPPresent) {
				arrOP[idx].setUDPResult(NO_ANSWER_YET);
			}
	}
	bContinueSniffing = true;

}

void Scanner::Begin()
{
	pthread_create(&recvThrd,NULL,&Scanner::PreparePacketScanner,(void *)this);
	pthread_create(&recvLBThrd,NULL,&Scanner::PrepareLoopBackPS,(void *)this);
	
	for(int i=0;i<num_threads;i++)
	{
		pthread_create(&scanThrd,NULL,&Scanner::Scan,(void *)this);
	}
	pthread_join(scanThrd,NULL);
	
	sleep(10);
	bContinueSniffing = false;
	pthread_join(recvLBThrd,NULL);
	pthread_join(recvThrd,NULL);
	
	cout<<"Results for IP-"<<dest_ip<<endl;
	for (int idx=0;idx<portOPLen;idx++) {
		if(!(strcmp(arrOP[idx].GetOutputMessage().c_str(),"EMPTY") ==0))
		{
			cout<<arrOP[idx].GetOutputMessage()<<endl;
		}
	}
	
	if(modes[5] == true) {
		cout<<"Protocol Scan"<<endl;
		for (int idx=1;idx<256;idx++) {
			if(idx != 17) {
				if (arrProtocolOP[idx] != UN_USED) {
					if (arrProtocolOP[idx] ==RESPNDED) {
						cout<<"Protocol:"<<idx<<"-Responsive"<<endl;
					} else if(arrProtocolOP[idx] == NRESPNDED) {
						cout<<"Protocol:"<<idx<<"-Non-Responsive(ICMP)"<<endl;
					} else if(arrProtocolOP[idx] == NO_ANSWER_Y || arrProtocolOP[idx] == PROCESSED) {
						cout<<"Protocol:"<<idx<<"-Non-Responsive(TimeOut)"<<endl;
					}
				}	
			}

		}
	}
}




int Scanner::GetSocket()
{
	int sockfd = 0;
	int on = 1;

	sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) {
		perror("socket");
		return (0);
	}
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) {
		perror("setsockopt");
		return (0);
	}
	return sockfd;
}



void* Scanner::Scan(void* obj)
{
	
	Scanner* scn = (Scanner*)obj;
	Stack* portStack = scn->getPortStack();
	int port = 0;
	while(true)
	{

		pthread_mutex_lock(&scn->lock);
		if(portStack->isEmpty())
		{
			pthread_mutex_unlock(&scn->lock);
			break;
		}
		port = portStack->pop();
		pthread_mutex_unlock(&scn->lock);
	
		if(port != 0)
		{
			if(scn->getModes()[0] == true)
				scn->SendPacket(port,(char*)"SYN");
			if(scn->getModes()[1] == true)
				scn->SendPacket(port,(char*)"NULL");
			if(scn->getModes()[2] == true)
				scn->SendPacket(port,(char*)"FIN");
			if(scn->getModes()[3] == true)
				scn->SendPacket(port,(char*)"XMAS");
			if(scn->getModes()[4] == true)
				scn->SendPacket(port,(char*)"ACK");
			if(scn->getModes()[5] == true)
			{
				int len = scn->getPrtclsLen();
				int* prtcls = scn->getPrtcls();
				string tmp;
				ostringstream conv;

				for(int i=0;i<len;i++)
				{
					pthread_mutex_lock(&scn->lock);
					bool flag = false;
					if(scn->arrProtocolOP[prtcls[i]] == NO_ANSWER_YET)
					{
						flag = true;
						scn->arrProtocolOP[prtcls[i]] = PROCESSED;
					}
					pthread_mutex_unlock(&scn->lock);
					
					if(prtcls[i] == 17  || flag)
					{
						
						conv << prtcls[i];
						tmp = conv.str();

						const char* mode = tmp.c_str();
						scn->SendPacket(port,(char *)mode);
						conv.str("");
						conv.clear();

						
					}

				}

			}
		}
	}
	return 0;
}





void Scanner::SendPacket(int port,char* mode)
{
	int retval = 0;
	Packet* pkt = new Packet(dest_ip,port,mode);
	iphdr* ipHeader = pkt->getIpHeader();
	sockaddr_in dest_net_addr = pkt->getDestNetAddr();
	char datagram[PKT_LEN];
	memcpy(datagram,pkt->getPacket(),PKT_LEN);
	int retries = 3;
	bool flag = false;

	if(strcmp(mode,"0") == 0 || atoi(mode) > 0)
		retries = 1;

	while(retries>0)
	{
		//cout<<"Port :"<<port<<" Retry :"<<retries<<" Mode :"<<mode<<endl;
		retval = sendto(sockfd,datagram,ipHeader->tot_len,0,(struct sockaddr*)&dest_net_addr,sizeof(dest_net_addr));
		if(retval == -1)
		{
			retries--;
			continue;
		}
		sleep(4);
		if(CheckForResponses(dest_ip,port,mode))
		{
			
			flag = true;
			break;
		}
		else
			retries--;
	}
	
	if(!flag)
	{
		if(retries <= 0) {
			for (int idx=0;idx<portOPLen;idx++) {
				if (arrOP[idx].getPort() == port) {
					if (strcmp(mode,"SYN") == 0) {
						arrOP[idx].setSyn(true);
						arrOP[idx].setSYNResult(FILTERED);
					} else if(strcmp(mode,"NULL") == 0) {
						arrOP[idx].setNul(true);
						arrOP[idx].setNULLResult(FILTERED);
					} else if(strcmp(mode,"FIN") == 0) {
						arrOP[idx].setFin(true);
						arrOP[idx].setFINResult(FILTERED);
					} else if(strcmp(mode,"XMAS") == 0) {
						arrOP[idx].setXmas(true);
						arrOP[idx].setXMASResult(FILTERED);
					} else if(strcmp(mode,"ACK") == 0) {
						arrOP[idx].setAck(true);
						arrOP[idx].setACKResult(FILTERED);
					} 
				}
			}
		}
	}
}





bool Scanner::CheckForResponses(string ip, int port, char* mode)
{
	for(int i=0;i<portOPLen;i++)
	{
		if(arrOP[i].getPort() == port)
		{
			if(arrOP[i].isFlagSetFor(mode))
			{
				return true;
			}
			return false;
		}
	}
	return false;
}






void ProcessPacket(u_char *arg,const struct pcap_pkthdr* pkthdr, const u_char* packet){

	Scanner* scn = (Scanner*)arg;
	struct iphdr *ipHeader =(struct iphdr *)(packet+sizeof(struct ethhdr));
	
	if (!scn->bContinueSniffing) {
		pcap_breakloop(scn->pDescr);
		pcap_breakloop(scn->pLBDescr);
		return;	
	}
	
	switch(ipHeader->protocol)
	{
		case 1:
		{	
			struct sockaddr_in src,dest;
			memset(&src,0,sizeof(src));
			src.sin_addr.s_addr = ipHeader->saddr;
			memset(&dest,0,sizeof(dest));
			dest.sin_addr.s_addr = ipHeader->daddr;
	
			if (strcmp(scn->getDestIp(),inet_ntoa(src.sin_addr)) == 0) {
				struct icmphdr *icmpHeader=(struct icmphdr*)(packet+(ipHeader->ihl*4)+sizeof(struct ethhdr));
				int type =(int)icmpHeader->type;
	
				struct iphdr *ipHdrIn =(struct iphdr *)(packet+sizeof(icmpHeader)+(ipHeader->ihl*4)+sizeof(struct ethhdr));
	
				int protocol_no = (long)ipHdrIn->protocol;
				if (protocol_no>0 && protocol_no<256) {
					scn->arrProtocolOP[protocol_no] = NRESPNDED;	
				}
	
				if(protocol_no == 6) {
					if( type == ICMP_DEST_UNREACH) {
						int code = (int)icmpHeader->code;
						if (code ==1 || code ==2 || code==3 || code==9 || code==10 || code==13) {
							struct tcphdr *tcpHdrIn=(struct tcphdr*)
																(packet+(ipHdrIn->ihl*4)+sizeof(icmpHeader)+(ipHeader->ihl*4)+sizeof(struct ethhdr));
							int iSourcePort = ntohs(tcpHdrIn->source);
							int iDestinationPort = ntohs(tcpHdrIn->dest) ;
	
							for (int idx=0;idx<scn->portOPLen;idx++){ 
								if (scn->arrOP[idx].getPort() == iDestinationPort) {
									switch(iSourcePort) {
									case SYN_PORT:
									{
										if(!scn->arrOP[idx].isSyn()) {
											scn->arrOP[idx].setSyn(true);
											scn->arrOP[idx].setSYNResult(FILTERED_ICMP);
											return;
										}
										break;
									}
									case NULL_PORT:
									{
										if(!scn->arrOP[idx].isNul()) {
											scn->arrOP[idx].setNul(true);
											scn->arrOP[idx].setNULLResult(FILTERED_ICMP);
										}
										// ICMP and Re-Trans - Filtered
										break;
									}
									case FIN_PORT:
									{
										if(!scn->arrOP[idx].isFin()) {
											scn->arrOP[idx].setFin(true);
											scn->arrOP[idx].setFINResult(FILTERED_ICMP);
	
										}
										// ICMP and Re-Trans - Filtered
										break;
									}
									case XMAS_PORT:
									{
										//cout<<"Got XMAS Reply"<<endl;
										if(!scn->arrOP[idx].isXmas()) {
											scn->arrOP[idx].setXmas(true);
											scn->arrOP[idx].setXMASResult(FILTERED_ICMP);
	
										}
										// ICMP and Re-Trans - Filtered
										break;
									}
									case ACK_PORT:
									{
										//cout<<"Got ACK Reply"<<endl;
										if(!scn->arrOP[idx].isAck()) {
											scn->arrOP[idx].setAck(true);
											scn->arrOP[idx].setACKResult(FILTERED_ICMP);
										}
										// ICMP and Re-Trans - Filtered
										break;
									}
									default:
										break;
									}
								}
							}
						}
					}
				}
	
				if(protocol_no == 17) {
					struct udphdr *udpHeader=(struct udphdr*)
										(packet+(ipHdrIn->ihl*4)+sizeof(icmpHeader)+(ipHeader->ihl*4)+sizeof(struct ethhdr));
					int iDestPort = ntohs(udpHeader->dest);
	
					for (int idx=0;idx<scn->portOPLen;idx++){ 
						if (scn->arrOP[idx].getPort() == iDestPort) {
							scn->arrOP[idx].setUDPResult(CLOSED);
						}
					}
				}
			}
			break;
		}
		case 6:
		{
			struct sockaddr_in src,dest;
			memset(&src,0,sizeof(src));
			src.sin_addr.s_addr = ipHeader->saddr;
			memset(&dest,0,sizeof(dest));
			dest.sin_addr.s_addr = ipHeader->daddr;
	
	
			struct tcphdr *tcpHeader=(struct tcphdr*)(packet+(ipHeader->ihl*4)+sizeof(struct ethhdr));
	
			int ackFlag = tcpHeader->ack;
			int rstFlag = tcpHeader->rst;
			int synFlag = tcpHeader->syn;
	
			if (strcmp(scn->getDestIp(),inet_ntoa(src.sin_addr)) == 0) {
				int iSourcePort = ntohs(tcpHeader->source);
				int iDestinationPort = ntohs(tcpHeader->dest) ;
	
				for (int idx=0;idx<scn->portOPLen;idx++){ 
					if (scn->arrOP[idx].getPort() == iSourcePort) {
						switch(iDestinationPort) {
						case SYN_PORT:
						{
							if(!scn->arrOP[idx].isSyn()) {
								scn->arrOP[idx].setSyn(true);
								if ((synFlag == 1) || (synFlag == 1 && ackFlag == 1)) {
									scn->arrOP[idx].setSYNResult(OPEN);
									return;
								}
								if (rstFlag == 1) {
									scn->arrOP[idx].setSYNResult(CLOSED);
									return;
								}
							}
							break;
						}
						case NULL_PORT:
						{
							if(!scn->arrOP[idx].isNul()) {
								scn->arrOP[idx].setNul(true);
								if (rstFlag == 1) {
									scn->arrOP[idx].setNULLResult(CLOSED);
								}
							}
							break;
						}
						case FIN_PORT:
						{
							if(!scn->arrOP[idx].isFin()) {
								scn->arrOP[idx].setFin(true);
								if (rstFlag == 1) {
									scn->arrOP[idx].setFINResult(CLOSED);
								}
							}
							break;
						}
						case XMAS_PORT:
						{
							if(!scn->arrOP[idx].isXmas()) {
								scn->arrOP[idx].setXmas(true);
								if (rstFlag == 1) {
									scn->arrOP[idx].setXMASResult(CLOSED);
								}
							}
							break;
						}
						case ACK_PORT:
						{
							if(!scn->arrOP[idx].isAck()) {
								scn->arrOP[idx].setAck(true);
								if (rstFlag == 1) {
									scn->arrOP[idx].setACKResult(UNFILTERED);
								}
							}
							break;
						}
						case PRTCL_PORT:
						{
							break;
						}
						default:
							break;
						}
					}
				}
			}
			break;
		}
		case 17:
		{
			struct sockaddr_in src,dest;
			memset(&src,0,sizeof(src));
			src.sin_addr.s_addr = ipHeader->saddr;
			memset(&dest,0,sizeof(dest));
			dest.sin_addr.s_addr = ipHeader->daddr;
			if (strcmp(scn->getDestIp(),inet_ntoa(src.sin_addr)) == 0) {
				struct udphdr *udpHeader=(struct udphdr*)(packet+(ipHeader->ihl*4)+sizeof(struct ethhdr));
				int iSourcePort = ntohs(udpHeader->source);
				for (int idx=0;idx<scn->portOPLen;idx++){
					if (scn->arrOP[idx].getPort() == iSourcePort) {
						scn->arrOP[idx].setUDPResult(OPEN);
					}
				}
			}
			break;
		}
		default:
		{
			int protocol_no = (long)ipHeader->protocol;
			struct sockaddr_in src,dest;
			memset(&src,0,sizeof(src));
			src.sin_addr.s_addr = ipHeader->saddr;
			memset(&dest,0,sizeof(dest));
			dest.sin_addr.s_addr = ipHeader->daddr;
	
			if (strcmp(scn->getDestIp(),inet_ntoa(src.sin_addr)) == 0) {
				if (protocol_no>0 && protocol_no<256) 
				{
					scn->arrProtocolOP[protocol_no] = RESPNDED;	
				}
			}
			break;
		}
	}
}


void* Scanner::PreparePacketScanner(void* obj) {
	
	Scanner* scn = (Scanner*)obj;
	char sErrorBuffer[PCAP_ERRBUF_SIZE];
	if ((scn->sSinffingDevice = pcap_lookupdev(sErrorBuffer)) == NULL) {
		cout<<sErrorBuffer<<endl;
		return 0;
	}
	
	if((scn->pDescr = pcap_open_live(scn->sSinffingDevice,MAXIMUM_BYTES,1,1000,sErrorBuffer)) == NULL) {
		cout<<sErrorBuffer<<endl;
		return 0;
	}

	
	if( pcap_loop(scn->pDescr,-1,ProcessPacket,(u_char*)scn) == -1) {
		return 0;
	}
	return 0;
}

void* Scanner::PrepareLoopBackPS(void* obj) {
	
	Scanner* scn = (Scanner*)obj;
	char sErrorBuffer[PCAP_ERRBUF_SIZE];
	if((scn->pLBDescr = pcap_open_live("lo",MAXIMUM_BYTES,1,1000,sErrorBuffer)) == NULL) {
		cout<<sErrorBuffer<<endl;
		return 0;
	}

	
	if( pcap_loop(scn->pLBDescr,-1,ProcessPacket,(u_char*)scn) == -1) {
		return 0;
	}
	return 0;
}

Scanner::~Scanner() {
	
}

