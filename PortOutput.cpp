#include "PortOutput.h"

PortOutput::PortOutput()
{

}

PortOutput::PortOutput(int p,bool* modes)
{

	port = p;

	for (int idx=0; idx<6; idx++)
	{
		switch(idx)
		{
		case _SYN:
			if(modes[idx] == true) {
				syn_result = NO_ANSWER_YET;
				syn = false;
			}
			else {
				syn_result =NOT_USED;
				syn = true;
			}
			break;

		case _NULL:
			if(modes[idx] == true) {
				null_result = NO_ANSWER_YET;
				nul = false;
			}

			else {
				null_result = NOT_USED;
				nul = true;
			}

			break;

		case _FIN:
			if(modes[idx] == true) {
				fin_result = NO_ANSWER_YET;
				fin = false;
			}

			else
			{fin_result = NOT_USED;
			fin = true;}
			break;

		case _XMAS:
			if(modes[idx] == true)
			{
				xmas_result = NO_ANSWER_YET;
				xmas = false; }
			else
			{
				xmas_result = NOT_USED;
				xmas=true;
			}

			break;

		case _ACK:
			if(modes[idx] == true) {
				ack_result  = NO_ANSWER_YET;
				ack = false;

			}
			else {
				ack_result = NOT_USED;
				ack = true;

			}
			break;
		
		}
		udp_result = NOT_USED;
	}
}

PortOutput::~PortOutput() {
}


bool PortOutput::isFlagSetFor(char* mode)
{
	if(strcmp(mode,"SYN")==0)
		return syn;
	if(strcmp(mode, "ACK")==0)
		return ack;
	if(strcmp(mode, "NULL")==0)
		return nul;
	if(strcmp(mode, "XMAS")==0)
		return xmas;
	if(strcmp(mode, "FIN")==0)
		return fin;
	return false;
}




char* PortOutput::ReturnStringResult(int result) {
	switch (result){
		case OPEN:
			return (char*)"OPEN";
		case CLOSED:
			return (char*)"CLOSED";
		case FILTERED:
			return (char*)"FILTERED";
		case FILTERED_ICMP:
			return (char*)"FILTERED_ICMP";
		case UNFILTERED:
			return (char*)"UNFILTERED";
		case OPEN_FILTERED:
			return (char*)"OPEN AND FILTERED";
		case NO_ANSWER_YET:
			return (char*)"NO ANSWER YET";
		default:
			return (char*)"Error";
			break;
	}
	
}

string PortOutput::GetOutputMessage() {
	sOutputMessage = port;
	ostringstream convertStream;   
	convertStream << "Port:";
	convertStream << port;
	int max = 0;
	
	if((syn_result == NOT_USED) && (ack_result == NOT_USED)
			&& (fin_result == NOT_USED) && (null_result == NOT_USED) 
			&& (xmas_result == NOT_USED) && (udp_result == NOT_USED)) {
		return "EMPTY";
	}
	
	if (!(syn_result == NOT_USED)) {
		convertStream<<"\tSYN=";
		convertStream<<ReturnStringResult(syn_result);
		if(max<syn_result) {
			max=syn_result;
		}
	}
	
	if(!(ack_result == NOT_USED)) {
		convertStream<<"\tACK=";
		convertStream<<ReturnStringResult(ack_result);
		if(max<ack_result) {
			max = ack_result;
		}
	}

	if(!(fin_result == NOT_USED)) {
		convertStream<<"\tFIN=";
		convertStream<<ReturnStringResult(fin_result);
		if(max<fin_result) {
			max = fin_result;
		}
	}

	if(!(null_result == NOT_USED)) {
		convertStream<<"\tNULL=";
		convertStream<<ReturnStringResult(null_result);
		if(max<null_result) {
			max = null_result;
		}
	}
	
	if (!(xmas_result == NOT_USED)) {
		convertStream<<"\tXMAS=";
		convertStream<<ReturnStringResult(xmas_result);
		if(max<xmas_result) {
			max = xmas_result;
		}
	}
	
	if (!(udp_result == NOT_USED)) {
		convertStream<<"\tUDP=";
		if(udp_result == NO_ANSWER_YET) {
			convertStream<<"Closed";
		} else {
			convertStream<<ReturnStringResult(udp_result);
		}
	}
	
	convertStream<<"\tFinal=";
	convertStream<<ReturnStringResult(max);
	
	convertStream<<"\n";
	//Add cummulative answer based on logic and append
	sOutputMessage = convertStream.str();
	return sOutputMessage;
}
