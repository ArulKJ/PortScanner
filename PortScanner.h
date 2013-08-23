#include<iostream>
#include<sstream>
#include<stdlib.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <errno.h>
#include<stdio.h>
#include<pthread.h>

using namespace std;


#define PKT_LEN 4096
#define MAX_STACK_LEN 1024
#define MAXIMUM_PORTS 1024
#define MAXIMUM_SCAN_METHODS 6
#define MAXIMUM_PROTOCOL_RANGE 255
#define MAXIMUM_THREADS 25
#define ZERO 0
#define SYN_PORT 2000
#define NULL_PORT 2001
#define FIN_PORT 2002
#define XMAS_PORT 2003
#define ACK_PORT 2004
#define PRTCL_PORT 2005
#define MAXIMUM_BYTES 65536

#ifndef PORTSCANNER_H_
#define PORTSCANNER_H_

#include "Stack.h"
#include "PortScnParam.h"

extern pthread_mutex_t lock;

struct pseudohdr
{
	unsigned int src_addr;
	unsigned int dest_addr;
	char reserved;
	unsigned char protocol;
	unsigned short length;

	struct tcphdr tcp;
	struct udphdr udp;
	struct icmp ipc;
};

enum e_ScanMethod{
	_SYN,
	_NULL,
	_FIN,
	_XMAS,
	_ACK,
	_PROTOCOL
};

enum e_IPVersion{
	NUSED,
	IPv4,
	IPv6
};

enum e_Result{
	NOT_USED,
	NO_ANSWER_YET,
	FILTERED,
	FILTERED_ICMP,
	UNFILTERED,
	CLOSED,
	OPEN_FILTERED,
	OPEN
};

enum e_ProtocolResult {
	UN_USED,
	NO_ANSWER_Y,
	RESPNDED,
	NRESPNDED,
	PROCESSED
};

#endif /* PORTSCANNER_H_ */
