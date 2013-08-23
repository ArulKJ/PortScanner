#ifndef PORTSCNPARAM_H_
#define PORTSCNPARAM_H_

#include <iostream>
#include <string>
#include "PortScanner.h"

class PortScnParam{

public:
	static PortScnParam* getInstance();

	int GetPortListLength();
	int* GetPortList();

	int GetInputType();
	char* GetIP();
	int GetIPVersion();

	std::string GetPrefixIP();
	int GetPrefixIPVer();
	int GetPrefix();

	std::string GetFileName();

	int GetNoOfThreads();

	bool* GetScanValues();

	int GetProtocolRangeListLength();
	int* GetProtocolRangeList();

	void DisplayHelp();

	bool HandlePortDetails(char* input);
	bool HandleSpeedupDetails(char* input);
	bool ExtractScanMethod(int position,std::string Input);
	bool HandleScanDetails(char* input);
	bool HandleProtocolRange(char* input);
	bool HandleIP(char* input);
	bool HandlePrefix(char* input);
	bool HandleFile(char* input);
	bool InitializePortScanParameters(int argc,char* argv[]);

	
private:
	static PortScnParam* m_pInstance;
	PortScnParam();

	int m_iPortListLength;
	int m_iPortList[MAXIMUM_PORTS];

	std::string m_sIp;
	int m_iIPVersion;

	std::string m_sPrefixIp;
	int m_iPrefixIPVersion;
	int m_iPrefix;

	std::string m_sFileName;


	int m_iNoOfThreads;

	bool m_bScanValues[MAXIMUM_SCAN_METHODS];

	int m_iProtocolRangeListLength;
	int m_iProtocolRangeList[MAXIMUM_PROTOCOL_RANGE];

};

#endif /* PORTSCNPARAM_H_ */
