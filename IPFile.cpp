#include "IPFile.h"
#include <fstream>

IPFile::IPFile() {

}


IPFile::IPFile(string path)
{
	char *loc;
	memcpy(&loc,&path,sizeof(path));

	ifstream ipFile;
	ipFile.open(loc,ios::in);
	string line;

	if(ipFile.is_open())
	{
		while(getline(ipFile,line))
		{
			strIPs += line + "|";
		}
	}
	ipFile.close();
}



char* IPFile::GetNextIP()
{
	if(strIPs.length() > 1)
	{
		char* ip;
		string tmp = strIPs.substr(0,strIPs.find("|",0));
		strIPs = strIPs.substr(strIPs.find("|",0) + 1);

		memcpy(&ip,&tmp,sizeof(tmp));
		return ip;

	}
	else
		return (char*)"EMPTY";
	return (char*)"EMPTY";
}



IPFile::~IPFile() {
}

