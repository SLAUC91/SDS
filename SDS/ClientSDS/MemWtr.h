#ifndef __MemWtr_H__
#define __MemWtr_H__

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include "Ntdll.h"

//
typedef enum {
	ITYPE_INT = 0,
	ITYPE_BOOL = 1,
	ITYPE_SHORT = 2,
	ITYPE_FLOAT = 3,
	ITYPE_BYTE = 4,
	ITYPE_POINTER = 5,
	ITYPE_STRING = 6,
	ITYPE_WSTRING = 7
} instructionType;

//
typedef struct {
	instructionType			itype;	//Type of Instruction
	PVOID					iInst;	//Pointer to the Instruction
} instruction_info;

//
typedef struct {
	std::vector<instruction_info>	params;
	ULONG						calladdress;
} init_buffer;

//BYTE buffer containing our instructions
typedef std::vector<BYTE> _thread_buffer;

class MemWtr
{
public:
	void					SetProcess(HANDLE hP) { hProc = hP; }
	HANDLE					GetProcessHandle() { return hProc; }

	void					PushInt(int);
	void					PushBool(bool);
	void					PushShort(short);
	void					PushFloat(float);
	void					PushByte(BYTE);
	void					PushPointer(PVOID);
	void					PushANSIString(PCHAR);
	void					PushUNICODEString(PWCHAR);
	void					PushCall(FARPROC);

	_thread_buffer			InitializeThreadBuffer();
	bool					WriteThreadBuffer(_thread_buffer, bool async = true);

	PVOID					WtrMem(PVOID data, size_t size_of_data);

protected:

	HANDLE					CreateThreadInTargetProcess(LPTHREAD_START_ROUTINE, LPVOID);

	void					AddByteToBuffer(BYTE);
	void					AddLongToBuffer(ULONG);

	void					PushParameter(instructionType, PVOID);
	void					PushAllParameters(bool rtCondition = true);

protected:
	HANDLE					hProc;
	init_buffer				CurrentObjBuffer;
	_thread_buffer			m_CurrentRemoteThreadBuffer;
};

#endif