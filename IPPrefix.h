#include "PortScanner.h"
#include <math.h>


#ifndef IPPREFIX_H_
#define IPPREFIX_H_

class IPPrefix
{

private:
	long int currentIP;
	int ipIndex;
	int totalHosts;

public:

	IPPrefix();

	IPPrefix(string sIP, int netBits);

	char* GetNextIP();

	virtual ~IPPrefix();
};

#endif /* IPPREFIX_H_ */
