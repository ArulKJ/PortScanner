#include "PortScnParam.h"
#include <string.h>
#include <stdlib.h>
#include <fstream>
#include <arpa/inet.h>
using namespace std;

PortScnParam* PortScnParam::m_pInstance = NULL;

PortScnParam* PortScnParam::getInstance() {
	if (!m_pInstance) {
		m_pInstance = new PortScnParam;
	}
	return m_pInstance;
}

PortScnParam::PortScnParam() {
		m_iPortListLength = MAXIMUM_PORTS;
		for (int idx = 0; idx<MAXIMUM_PORTS; idx++) {
			m_iPortList[idx] = idx+1;
		}

		m_iIPVersion = NUSED;
		m_iPrefix = 0;

		m_iPrefixIPVersion = NUSED;
		
		m_iNoOfThreads = 1;

		for (int idx = 0; idx<MAXIMUM_SCAN_METHODS; idx++) {
			m_bScanValues[idx] = true;
		}

		m_iProtocolRangeListLength = MAXIMUM_PROTOCOL_RANGE;
		for (int idx = ZERO; idx<MAXIMUM_PROTOCOL_RANGE; idx++) {
			m_iProtocolRangeList[idx] = idx+1;
		}

		m_sFileName = "EMPTY";
}

int PortScnParam::GetPortListLength(){
	return m_iPortListLength;
}

int* PortScnParam::GetPortList(){
	return m_iPortList;
}

char* PortScnParam::GetIP() {
	char* ip;
	memcpy(&ip,&m_sIp,sizeof(m_sIp));
	return ip;
}

int PortScnParam::GetIPVersion() {
	return m_iIPVersion;
}

string PortScnParam::GetPrefixIP() {
	return m_sPrefixIp;
}

int PortScnParam::GetPrefixIPVer() {
	return m_iPrefixIPVersion;
}

int PortScnParam::GetPrefix(){
	return 	m_iPrefix;
}

std::string PortScnParam::GetFileName(){
	return m_sFileName;
}


int PortScnParam::GetNoOfThreads() {
	return m_iNoOfThreads;
}


bool* PortScnParam::GetScanValues() {
	return m_bScanValues;
}


int PortScnParam::GetProtocolRangeListLength() {
	return m_iProtocolRangeListLength;
}

int* PortScnParam::GetProtocolRangeList(){
	return m_iProtocolRangeList;
}

void PortScnParam::DisplayHelp(){
	cout<<"\t\tPortScanner"<<endl;
	cout<<"--help : Will display help"<<endl;
	cout<<"--ports START_NO-END_NO (or) NO1,NO2 : Range is from 1 to 1024"<<endl;
	cout<<"--speedup No : Maximum of 25 allowed"<<endl;
	cout<<"--scan METHOD1,METHOD2 : SYN,NULL,ACK,FIN,XMAS,PROTOCOL allowed"<<endl;
	cout<<"--protocol-range START_NO-END_NO (or) NO1,NO2 : Range is from 1 to 255"<<endl;
	cout<<"--ip IP : IPv4 or IPv6 IP"<<endl;
	cout<<"--prefix IP/Prefix"<<endl; 
	cout<<"--file FILENAME"<<endl;
	return;
}

bool PortScnParam::HandlePortDetails(char* input) {

	bool bIsRange = false;
	bool bIsList = false;

	if (input != NULL) {

		string Input= input;

		int position = Input.find("-");
		if (position != (int)string::npos) {
			bIsRange = true;
		}

		position = Input.find(",");
		if (position != (int)string::npos) {
			bIsList = true;
		}

		if(bIsRange && bIsList){
			cout<<"Cannot have a range and a list at the same time\n";
			return false;
		}

		if(bIsRange) {
			position = Input.find("-");
			string portStartNo = Input.substr(ZERO,position);
			string portEndNo = Input.substr(position+1);

			for(int idx=ZERO; idx<(int)strlen(portStartNo.c_str());idx++) {
				if(!isdigit(portStartNo.c_str()[idx])){ //portStartNo.c_str()[idx]<48 || portStartNo.c_str()[idx]>57){
					cout<<"Invalid Characters in Port Start value\n";
					return false;
				}
			}

			for(int idx=ZERO; idx<(int)strlen(portEndNo.c_str());idx++) {
				if(!isdigit(portEndNo.c_str()[idx])){//portEndNo.c_str()[idx]<48 || portEndNo.c_str()[idx]>57){
					cout<<"Invalid Characters in Port End value\n";
					return false;
				}
			}

			int iPortStartNo = atoi(portStartNo.c_str());
			int iPortEndNo = atoi(portEndNo.c_str());
			if((iPortStartNo <= ZERO) || (iPortStartNo >MAXIMUM_PORTS) ) {
				cout<<"--ports start number is invalid\n";
				return false;
			}
			if((iPortEndNo <= ZERO) || (iPortEndNo > MAXIMUM_PORTS)){
				cout<<"--ports end number is invalid\n";
				return false;
			}
			if(iPortEndNo < iPortStartNo) {
				cout<<"--ports start number is greater than end number\n";
				return false;
			}

			int idx,portNo;
			for (idx=0,portNo=iPortStartNo;portNo<=iPortEndNo;idx++,portNo++) {
				m_iPortList[idx]=portNo;
			}
			m_iPortListLength=idx;
			cout<<"A range of Ports will be scaned from ";
			cout<<iPortStartNo<<" to "<<iPortEndNo<<endl;
			return true;
		}

		if (bIsList) {

			int idx = ZERO;
			while(Input.length() > ZERO) {

				position = Input.find(",");
				if (position == (int)string::npos) {
					for(int idx1=ZERO; idx1<(int)strlen(Input.c_str());idx1++) {
						if(!isdigit(Input.c_str()[idx1])){
							cout<<"Invalid Characters in Port value\n";
							return false;
						}
					}
					m_iPortList[idx++] = atoi(Input.c_str());
					if(m_iPortList[idx-1] <= ZERO || m_iPortList[idx-1] > MAXIMUM_PORTS ) {
						cout<<"Port No specified is invalid\n";
						return false;
					}
					break;
					
				}
				else{
					string temp = Input.substr(ZERO,position).c_str();
					for(int idx1=ZERO; idx1<(int)strlen(temp.c_str());idx1++) {
						if(!isdigit(temp.c_str()[idx1])){
							cout<<"Invalid Characters in Port value\n";
							return false;
						}
					}

					m_iPortList[idx++] = atoi(temp.c_str());
					if(m_iPortList[idx-1] <= ZERO || m_iPortList[idx-1] > MAXIMUM_PORTS) {
						cout<<"Port No specified is invalid\n";
						return false;
					}
					Input = Input.substr(position+1);
				}
			}
			m_iPortListLength=idx;
			cout<<"A list of Ports will be scanned\n[";
			for (int index=0;index<m_iPortListLength; index++) {
				cout<<m_iPortList[index]<<",";
			}
			cout<<"]"<<endl;
			return true;
		}

		if (!bIsRange && !bIsList) {
			for(int idx1=ZERO; idx1<(int)strlen(input);idx1++) {
				if(!isdigit(input[idx1])){
					cout<<"Invalid Characters in port value\n";
					return false;
				}
			}
			m_iPortListLength=1;

			m_iPortList[0] = atoi(input);
			if(m_iPortList[0] <= ZERO || m_iPortList[0] > MAXIMUM_PORTS) {
				cout<<"Port No specified is invalid\n";
				return false;
			}
			cout<<"The following port will be scanned:"<<m_iPortList[0]<<endl;
			return true;
		}

		cout<<"generic problem in --ports values\n";
		return false;
	}
	else
	{
		cout<<"No values passed for the --ports parameter\n";
		return false;
	}
	return false;
}


bool PortScnParam::HandleSpeedupDetails(char* input) {

	if (input != NULL) {
		for(int idx=ZERO;idx<(int)strlen(input); idx++) {
			if(!isdigit(input[idx])){
				cout<<"Invalid Characters in speedup value\n";
				return false;
			}
		}
		m_iNoOfThreads = atoi(input);

		
		if((m_iNoOfThreads <= ZERO) || (m_iNoOfThreads >MAXIMUM_THREADS) ) {
			cout<<"--speedup value is invalid.\n";
			return false;
		}
		cout<<"Number of Concurrent Threads allowed:"<<m_iNoOfThreads<<endl;
		return true;
	} else {
		cout<<"No values passed for the --speedup parameter\n";
		return false;
	}
}

bool PortScnParam::ExtractScanMethod(int position,string Input) {
	if (Input == "SYN") {
		m_bScanValues[_SYN]=true;
	} else if(Input == "NULL") {
		m_bScanValues[_NULL]=true;
	} else if(Input == "FIN") {
		m_bScanValues[_FIN]=true;
	} else if(Input == "XMAS") {
		m_bScanValues[_XMAS]=true;
	} else if(Input == "ACK") {
		m_bScanValues[_ACK]=true;
	} else if(Input == "PROTOCOL") {
		m_bScanValues[_PROTOCOL]=true;
	} else {
		cout<<"Error in scan method passed to ExtractScanMethod \n";
		return false;
	}
	return true;
}

bool PortScnParam::HandleScanDetails(char* input) {
	if (input != NULL) {
		for (int idx=0;idx<MAXIMUM_SCAN_METHODS;idx++) {
			m_bScanValues[idx] = false;
		}

		string Input= input;
		int position = Input.find(",");
		if (position== (int)string::npos) {
			if(!ExtractScanMethod(0,Input)) {
				cout<<"Error in single param for scan\n";
				return false;
			}

			return true;
		}
		else{
			int idx = ZERO;
			while(Input.length() > ZERO) {
				position = Input.find(",");
				if (position == (int)string::npos) {
					if(!ExtractScanMethod(idx++,Input)) {
						cout<<"Error in last param for scan\n";
						return false;
					}
					break;
				}
				else{
					string temp = Input.substr(ZERO,position).c_str();
					if(!ExtractScanMethod(idx++,temp)) {
						cout<<"Error in comma param for scan\n";
						return false;
					}

					Input = Input.substr(position+1);
				}
			}

			return true;
		}
		cout<<"generic problem in --scans values\n";
		return false;
	}
	else
	{
		cout<<"No values passed for the --ports parameter\n";
		return false;
	}

}

bool PortScnParam::HandleProtocolRange(char* input){

	bool bIsRange = false;
	bool bIsList = false;

	if (input != NULL) {

		string Input= input;

		int position = Input.find("-");
		if (position != (int)string::npos) {
			bIsRange = true;
		}

		position = Input.find(",");
		if (position != (int)string::npos) {
			bIsList = true;
		}

		if(bIsRange && bIsList){
			cout<<"Cannot have a range and a list at the same time\n";
			return false;
		}

		if(bIsRange) {
			position = Input.find("-");
			string protocolStartNo = Input.substr(ZERO,position);
			string protocolEndNo = Input.substr(position+1);

			for(int idx=ZERO; idx<(int)strlen(protocolStartNo.c_str());idx++) {
				if(!isdigit(protocolStartNo.c_str()[idx])){
					cout<<"Invalid Characters in protocol-range Start value\n";
					return false;
				}
			}

			for(int idx=ZERO; idx<(int)strlen(protocolEndNo.c_str());idx++) {
				if(!isdigit(protocolEndNo.c_str()[idx])){
					cout<<"Invalid Characters in protocol-range End value\n";
					return false;
				}
			}

			int protocolRangeStartNo = atoi(protocolStartNo.c_str());
			int protocolRangeStopNo = atoi(protocolEndNo.c_str());
			if((protocolRangeStartNo <= ZERO) || (protocolRangeStartNo >MAXIMUM_PROTOCOL_RANGE)) {
				cout<<"--protocol-range start number is invalid\n";
				return false;
			}
			if((protocolRangeStopNo <= ZERO) || (protocolRangeStopNo > MAXIMUM_PROTOCOL_RANGE)){
				cout<<"--protocol-range end number is invalid\n";
				return false;
			}
			if(protocolRangeStopNo < protocolRangeStartNo) {
				cout<<"--protocol-range start number is greater than end number\n";
				return false;
			}
			int idx=0,prot_idx=0;
			for (idx=0,prot_idx=protocolRangeStartNo; prot_idx<=protocolRangeStopNo; idx++,prot_idx++) {
				m_iProtocolRangeList[idx]=prot_idx;
			}
			m_iProtocolRangeListLength = idx;
			cout<<"A range of Protocol Nos wil be scanned: ";
			cout<<protocolRangeStartNo<<" to "<<protocolRangeStopNo<<endl;
			return true;
		}

		if (bIsList) {

			int idx = ZERO;
			while(Input.length() > ZERO) {

				position = Input.find(",");
				if (position == (int)string::npos) {
					for(int idx1=ZERO; idx1<(int)strlen(Input.c_str());idx1++) {
						if(Input.c_str()[idx1]<48 || Input.c_str()[idx1]>57){
							cout<<"Invalid Characters in protocol-range value\n";
							return false;
						}
					}
					m_iProtocolRangeList[idx++] = atoi(Input.c_str());
					if(m_iProtocolRangeList[idx-1] <= ZERO || m_iProtocolRangeList[idx-1] > MAXIMUM_PROTOCOL_RANGE ) {
						cout<<"Invalid Protocol Number\n";
						return false;
					}
					break;
				}
				else{
					string temp = Input.substr(ZERO,position).c_str();
					for(int idx1=ZERO; idx1<(int)strlen(temp.c_str());idx1++) {
						if(temp.c_str()[idx1]<48 || temp.c_str()[idx1]>57){
							cout<<"Invalid Characters in protocol-range value\n";
							return false;
						}
					}

					m_iProtocolRangeList[idx++] = atoi(temp.c_str());
					if(m_iProtocolRangeList[idx-1] <= ZERO || m_iProtocolRangeList[idx-1] > MAXIMUM_PROTOCOL_RANGE) {
						cout<<"Invalid Protocol Number\n";
						return false;
					}
					Input = Input.substr(position+1);
				}
			}
			m_iProtocolRangeListLength=idx;
			cout<<"A list of protocol-nos will be scanned:[";
			for (int index=0;index<m_iProtocolRangeListLength; index++) {
				cout<<m_iProtocolRangeList[index]<<",";
			}
			cout<<"]"<<endl;
			return true;
		}

		if (!bIsRange && !bIsList) {
			for(int idx1=ZERO; idx1<(int)strlen(input);idx1++) {
				if(!isdigit(input[idx1])) {
					cout<<"Invalid Characters in protocol-range value\n";
					return false;
				}
			}
			m_iProtocolRangeListLength=1;

			m_iProtocolRangeList[0] = atoi(input);
			if(m_iProtocolRangeList[0] <= ZERO || m_iProtocolRangeList[0] > MAXIMUM_PROTOCOL_RANGE) {
				cout<<"Invalid Protocol Number\n";
				return false;
			}

			cout<<"Will scan for the following protocol-number:";
			cout<<m_iProtocolRangeList[0]<<endl;
			return true;
		}

		cout<<"generic problem in --protocol-range values\n";
		return false;
	}
	else
	{
		cout<<"No values passed for the --ports parameter\n";
		return false;
	}
}

bool PortScnParam::HandleIP(char* input){
	if(input != NULL) {
		struct in6_addr sa;
		if(inet_pton(AF_INET,input,&sa) > 0) {
			m_sIp = input;
			m_iIPVersion = IPv4;
			cout<<"We will scan for an IPv4 IP:"<<m_sIp.c_str()<<endl;
			return true;
		}

		struct sockaddr_in saIPv6;
		if(inet_pton(AF_INET6,input,&saIPv6) > 0) {
			m_sIp = input;
			m_iIPVersion = IPv6;
			cout<<"We will scan for an IPv6 IP:"<<m_sIp.c_str()<<endl;
			return true;
		}

		cout<<"Some error in IP\n";
		return false;
	}
	else
	{
		cout<<"No values passed for the --ip parameter\n";
		return false;
	}
}

bool PortScnParam::HandlePrefix(char* input){
	if(input != NULL) {
		string Input=input;

		int position = Input.find("/");
		string ip = Input.substr(ZERO,position);
		string prefix = Input.substr(position+1);


		bool validIp = false;
		struct in6_addr sa;
		if(inet_pton(AF_INET,(char*)ip.c_str(),&sa) == 1) {
			m_sPrefixIp = ip;
			m_iPrefixIPVersion = IPv4;
			validIp = true;
		}

		if(inet_pton(AF_INET6,(char*)ip.c_str(),&sa) == 1) {
			m_sPrefixIp = ip;
			m_iPrefixIPVersion = IPv6;
			validIp = true;
		}

		if (!validIp) {
			cout<<"Error in Ip given for --prefix option"<<endl;
			return false;
		}


		for(int idx=ZERO; idx<(int)strlen(prefix.c_str());idx++) {
			if(!isdigit(prefix.c_str()[idx])){
				cout<<"Invalid Characters in Prefix  value\n";
				return false;
			}
		}

		int position1 = m_sPrefixIp.find(".");
		string firstOctet = Input.substr(ZERO,position1);
		int iFOctet = atoi(firstOctet.c_str());

		m_iPrefix=atoi(prefix.c_str());
		if(m_iPrefixIPVersion == IPv4 && iFOctet>0 && iFOctet<=127) {
			if(m_iPrefix < 8 || m_iPrefix>32) {
				cout<<"For a Class A, we cannot have prefix less than 8"<<endl;
				return false;
			}
		}

		if(m_iPrefixIPVersion == IPv4 && iFOctet>127 && iFOctet<=191) {
			if(m_iPrefix < 16 || m_iPrefix>32) {
				cout<<"For a Class B, we cannot have prefix less than 16"<<endl;
				return false;
			}
		}

		if(m_iPrefixIPVersion == IPv4 && iFOctet>191 && iFOctet<=223) {
			if(m_iPrefix < 24 || m_iPrefix>32) {
				cout<<"For a Class C, we cannot have prefix less than 24"<<endl;
				return false;
			}
		}
		
		if (((m_iPrefixIPVersion == IPv4)
				|| (m_iPrefixIPVersion == IPv6 && m_iPrefix > 0  && m_iPrefix<128))) {
			cout<<"Will scan IP/prefix:"<<m_sPrefixIp<<"/"<<m_iPrefix<<endl;
			return true;
		}
		else {
			cout<<"Invalid Prefix Value\n"<<endl;
			return false;
		}

	} else {
		cout<<"No values passed for the --prefix parameter\n";
		return false;
	}
}

bool PortScnParam::HandleFile(char* input){
	if(input != NULL){
		ifstream inputFile(input);
		if(!inputFile.is_open()) {
			cout<<"Error opening the file. Non existent or wrong name\n";
			return false;
		}
		m_sFileName = input;
		return true;
	}
	else
	{
		cout<<"No values passed for the --file parameter\n";
		return false;
	}
}

bool PortScnParam::InitializePortScanParameters(int argc,char* argv[]) {
	bool bExploredParameter[argc];
	bool IpOrPrefixOrFile = false;

	bExploredParameter[ZERO] = true;
	for (int idx=1;idx <argc;idx++) {
		bExploredParameter[idx] = false;
	}

	for (int idx=1; idx<argc; idx++) {
		if (bExploredParameter[idx]) {
			continue;
		}


		if((strcmp(argv[idx],"--help") == ZERO) && (idx==1)) {
			DisplayHelp();
			return true;
		}

		if(strcmp(argv[idx],"--ports")==ZERO) {

			bExploredParameter[idx] = true;
			bExploredParameter[idx+1] = true;
			if (!HandlePortDetails(argv[idx+1])) {
				// TODO some error in port values. Print and exit
				return false;
			}
		}

		if(strcmp(argv[idx],"--speedup")==ZERO) {

			bExploredParameter[idx] = true;
			bExploredParameter[idx+1] = true;
			if (!HandleSpeedupDetails(argv[idx+1])) {
				return false;
			}
		}

		if(strcmp(argv[idx],"--scan")==ZERO) {
			bExploredParameter[idx] = true;
			bExploredParameter[idx+1] = true;
			if (!HandleScanDetails(argv[idx+1])) {
				return false;
			}
		}

		if(strcmp(argv[idx],"--protocol-range")==0) {
			bExploredParameter[idx] = true;
			bExploredParameter[idx+1] = true;
			if (!HandleProtocolRange(argv[idx+1])) {
				return false;
			}
		}

		if(strcmp(argv[idx],"--ip") == 0) {
			bExploredParameter[idx] = true;
			bExploredParameter[idx+1] = true;
			IpOrPrefixOrFile = true;
			if (!HandleIP(argv[idx+1])) {
				return false;
			}
			cout<<"Returned correctly\n";
		}

		if(strcmp(argv[idx],"--prefix") == 0) {
			bExploredParameter[idx] = true;
			bExploredParameter[idx+1] = true;
			IpOrPrefixOrFile = true;
			if (!HandlePrefix(argv[idx+1])) {
				return false;
			}
		}

		if(strcmp(argv[idx],"--file")==0) {
			bExploredParameter[idx] = true;
			bExploredParameter[idx+1] = true;
			IpOrPrefixOrFile = true;
			if (!HandleFile(argv[idx+1])) {
				return false;
			}
		}
	}

	if(!IpOrPrefixOrFile) {
		bool foundIP= false;
		
		for (int idx=ZERO;idx<argc;idx++) {
			if (!bExploredParameter[idx]) {
				bExploredParameter[idx] = true;
				foundIP = true;
				if (!HandleIP(argv[idx])) {
					return false;
				}
			}
		}
		if(!foundIP) {
			cout<<"No IP(or)Prefix(or)File Parameter found. Also singular ip not given\n";
			return false;
		}
	}


	for (int idx=ZERO;idx<argc;idx++) {
		if (!bExploredParameter[idx]) {
			cout<<"Some Random Value Found\n";
			return false;
		}
	}

	return true;
}


