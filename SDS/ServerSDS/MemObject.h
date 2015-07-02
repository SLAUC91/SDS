#ifndef __MemObject_H__
#define __MemObject_H__

#include <Windows.h>

class MemObject{
public:
	PBYTE buffer = NULL;
	ULONG bSize = 0;

	MemObject(ULONG bSize){
		this->buffer = new BYTE[bSize];
		this->bSize = bSize;
	}
	~MemObject(){
		delete buffer;
	}
};

#endif