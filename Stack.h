#include "PortScanner.h"

#ifndef STACK_H_
#define STACK_H_

class Stack
{
private:
	int tos;
	int arr[MAX_STACK_LEN];
	int count;

public:
	Stack();
	Stack(int* ports, int num);
	int pop();
	void push(int port);
	bool isEmpty();
	bool isFull();
	void reset();
	void setEmpty();
	virtual ~Stack();

	const int* getArr() const {
		return arr;
	}

	int getCount() const {
		return count;
	}
};

#endif /* STACK_H_ */
