#include "PortScanner.h"

#ifndef PORTOUTPUT_H_
#define PORTOUTPUT_H_

class PortOutput
{
private:
	int port;
	bool syn;
	bool ack;
	bool fin;
	bool nul;
	bool xmas;

	string sOutputMessage; 

	int syn_result;
	int ack_result;
	int fin_result;
	int null_result;
	int xmas_result;
	int udp_result;


public:
	PortOutput();
	PortOutput(int p,bool* modes); 
		
	virtual ~PortOutput();

	bool isFlagSetFor(char* mode);

	bool isAck() const {
		return ack;
	}

	void setAck(bool ack) {
		this->ack = ack;
	}

	bool isFin() const {
		return fin;
	}

	void setFin(bool fin) {
		this->fin = fin;
	}

	bool isNul() const {
		return nul;
	}

	void setNul(bool nul) {
		this->nul = nul;
	}

	int getPort() const {
		return port;
	}

	void setPort(int port) {
		this->port = port;
	}

	bool isSyn() const {
		return syn;
	}

	void setSyn(bool syn) {
		this->syn = syn;
	}

	bool isXmas() const {
		return xmas;
	}

	void setXmas(bool xmas) {
		this->xmas = xmas;
	}
	
	void setSYNResult(int result) {
		this->syn_result = result;
	}

	void setACKResult(int result) {
		this->ack_result = result;
	}

	void setNULLResult(int result) {
		this->null_result = result;
	}

	void setXMASResult(int result) {
		this->xmas_result = result;
	}

	void setFINResult(int result) {
		this->fin_result = result;
	}

	void setUDPResult(int result) {
		this->udp_result = result;
	}

	int getSYNResult() {
		return syn_result;
	}

	int getACKResult(){
		return ack_result;
	}

	int getNULLResult() {
		return null_result;
	}

	int getXMASResult() {
		return xmas_result;
	}

	int getFINResult() {
		return fin_result;
	}

	int getUDPResult() {
		return udp_result;
	}
	char* ReturnStringResult(int result);	 
	string GetOutputMessage();

};

#endif /* PORTOUTPUT_H_ */
