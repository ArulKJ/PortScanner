#include "PortScanner.h"
#include "Scanner.h"
#include "IPPrefix.h"
#include "IPFile.h"

using namespace std;


int main(int argc, char* argv[]) {
	cout<<"**********************Start***********"<<endl;
	PortScnParam* userArgs = PortScnParam::getInstance();
	if(argc <=1) {
		cout<<"No parameters present\n";
		return 0;
	}
	bool value = userArgs->InitializePortScanParameters(argc,argv);
	if (!value){
		userArgs->DisplayHelp();
		return -1;
	}

	

	if(userArgs->GetIPVersion() != NUSED)
	{
		char* ip = userArgs->GetIP();
		Scanner* scnr = new Scanner(userArgs,ip);
		scnr->Begin();
	}


	if(userArgs->GetPrefixIPVer() != NUSED)
	{
		IPPrefix* ipfx = new IPPrefix(userArgs->GetPrefixIP(),userArgs->GetPrefix());
		char *ip = ipfx->GetNextIP();
		
		while(strcmp(ip,"EMPTY") != 0)
		{
			Scanner* scnr = new Scanner(userArgs,ip);
			scnr->Begin();
			ip = ipfx->GetNextIP();
			
		}
	}


	if(userArgs->GetFileName() != "EMPTY")
	{
		IPFile* ipf = new IPFile(userArgs->GetFileName());
		char* ip = ipf->GetNextIP();

		while(strcmp(ip,"EMPTY") != 0)
		{
			cout<<"Scanning :"<<ip<<endl;
			Scanner* scnr = new Scanner(userArgs,ip);
			scnr->Begin();
			ip = ipf->GetNextIP();
		}
	}

	cout<<"********************Stop***************"<<endl;
	return 1;
}

