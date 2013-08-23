#include "PortScanner.h"

#ifndef IPFILE_H_
#define IPFILE_H_

class IPFile
{

private:
	string strIPs;

public:
	IPFile();
	IPFile(string path);
	char* GetNextIP();
	virtual ~IPFile();
};

#endif /* IPFILE_H_ */
