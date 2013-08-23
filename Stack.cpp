#include "Stack.h"

Stack::Stack()
{
	tos = -1;
	count = 0;
	for (int i=0;i<MAX_STACK_LEN; i++)
		arr[i] = 0;
}

Stack::Stack(int* items, int num)
{
	tos = -1;
	int i=0;

	count = num;

	for (int i=0;i<MAX_STACK_LEN; i++)
		arr[i] = 0;

	for(i=0;i<count;i++)
		push(items[i]);
}


void Stack::push(int port)
{
	if(!isFull())
	{
		tos++;
		arr[tos] = port;
	}
}


int Stack::pop()
{
	int val = 0;

	if(!isEmpty())
		val = arr[tos--];

	return val;
}



bool Stack::isEmpty()
{
	bool ret = false;

	if(tos == -1)
		ret = true;
	else
		ret = false;

	return ret;
}



bool Stack::isFull()
{
	bool ret = false;

	if(tos == count)
		ret = true;
	else
		ret = false;

	return ret;
}



void Stack::reset()
{
	tos = 0;
}


void Stack::setEmpty()
{
	tos = -1;
}

Stack::~Stack() {

}

