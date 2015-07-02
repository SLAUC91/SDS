#include "MemWtr.h"

//Used as reference for assembly: http://x86.renejeschke.de/

void MemWtr::PushParameter(instructionType insType, PVOID instruction)
{
	instruction_info instruct_Obj;
	instruct_Obj.itype = insType;
	instruct_Obj.iInst = instruction;
	//printf("Adding parameter to function [%i][0x%X]\n", instruct_Obj.itype, instruct_Obj.iInst);
	CurrentObjBuffer.params.push_back(instruct_Obj);
}

void MemWtr::PushInt(int a)
{
	int * iB = new int;
	*iB = a;
	PushParameter(ITYPE_INT, iB);
}

void MemWtr::PushBool(bool a)
{
	bool * bB = new bool;
	*bB = a;
	PushParameter(ITYPE_BOOL, bB);
}

void MemWtr::PushShort(short a)
{
	short * sB = new short;
	*sB = a;
	PushParameter(ITYPE_SHORT, sB);
}

void MemWtr::PushFloat(float a)
{
	float * fB = new float;
	*fB = a;
	PushParameter(ITYPE_FLOAT, fB);
}

void MemWtr::PushByte(BYTE a)
{
	PBYTE ucB = new BYTE;
	*ucB = a;
	PushParameter(ITYPE_BYTE, &ucB);
}

void MemWtr::PushPointer(PVOID p)
{
	PushParameter(ITYPE_POINTER, p);
}

void MemWtr::PushANSIString(PCHAR pSTR)
{
	PushParameter(ITYPE_STRING, pSTR);
}

void MemWtr::PushUNICODEString(PWCHAR pWSTR)
{
	PushParameter(ITYPE_WSTRING, pWSTR);
}

void MemWtr::PushCall(FARPROC CallAddress)
{
	printf("PushCall [0x%X]\n", CallAddress);
	//int iFunctionBegin = (int)CurrentObjBuffer.params.size();

	CurrentObjBuffer.calladdress = (ULONG)CallAddress;

	//Calling convention
	//printf("---STDCALL---\n");

	PushAllParameters(true);

	AddByteToBuffer(0xB8);			//MOV EAX VALUE
	AddLongToBuffer(CurrentObjBuffer.calladdress);
	AddByteToBuffer(0xFF);			//CALL
	AddByteToBuffer(0xD0);			//EAX

	//clear data
	CurrentObjBuffer.params.clear();
	CurrentObjBuffer.calladdress = NULL;
}

//StartThread buffer
_thread_buffer MemWtr::InitializeThreadBuffer()
{
	AddByteToBuffer(0x33);	//xor
	AddByteToBuffer(0xC0);	//EAX
	AddByteToBuffer(0xC2);	//ret
	AddByteToBuffer(0x04);	//4
	AddByteToBuffer(0x00);	//0
	return m_CurrentRemoteThreadBuffer;
}

bool MemWtr::WriteThreadBuffer(_thread_buffer ThrData, bool async)
{
	ULONG uMemSize = (ULONG)ThrData.size();
	PVOID pRemoteMem = VirtualAllocEx(hProc, NULL, uMemSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pRemoteMem == NULL)
		return false;

	PBYTE pnewBuffer = new BYTE[ThrData.size()];

	for (int i = 0; i < (int)ThrData.size(); i++)
	{
		memcpy(&pnewBuffer[i], &ThrData[i], sizeof(BYTE));
	}

	BOOL bWriteProcess = WriteProcessMemory(hProc, pRemoteMem, pnewBuffer, ThrData.size(), NULL);

	if (bWriteProcess == FALSE)
		return false;

	HANDLE hThreadHandle = CreateThreadInTargetProcess((LPTHREAD_START_ROUTINE)pRemoteMem, NULL);

	if (hThreadHandle == INVALID_HANDLE_VALUE)
		return false;

	if (async == true)
	{
		WaitForSingleObject(hThreadHandle, INFINITE);
	}

	VirtualFreeEx(hProc, pRemoteMem, uMemSize, MEM_RELEASE);
	memset(&CurrentObjBuffer, 0, sizeof(CurrentObjBuffer));
	m_CurrentRemoteThreadBuffer.clear();
	return true;
}

HANDLE MemWtr::CreateThreadInTargetProcess(LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam)
{
	//Your thread injection Method 
	//Common methods - CreateRemoteThread, NtCreateThreadEx, SuspendedThread

	//Keep in mind here that this can be easily seen by external monitoring programs
	//specifically that the thread creation call was from an outside process

	//Also keep Session Separation for OS > Vista in mind which may cause 
	//CreateRemoteThread to fail. NtCreateThreadEx is a nice alternative.


	//Try to create a NtCreateThreadEx
	if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"))
	{
		_NTbuffer Buffer;
		DWORD dw0 = 0;
		DWORD dw1 = 0;
		memset(&Buffer, 0, sizeof(_NTbuffer));

		Buffer.Size = sizeof(_NTbuffer);
		Buffer.Unknown1 = 0x10003;
		Buffer.Unknown2 = 0x8;
		Buffer.Unknown3 = &dw1;
		Buffer.Unknown4 = 0;
		Buffer.Unknown5 = 0x10004;
		Buffer.Unknown6 = 4;
		Buffer.Unknown7 = &dw0;

		NtCreateThreadEx_t NTCreateThread = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");

		if (NTCreateThread == NULL)
			return NULL;

		HANDLE hRemoteThread = NULL;

		if (!NT_SUCCESS(NTCreateThread(&hRemoteThread, 0x1FFFFF, NULL, hProc, lpThread, lpParam, FALSE, NULL, NULL, NULL, &Buffer)))
		{
			return NULL;
		}

		return hRemoteThread;
	}

	//Else - CreateRemoteThread
	return CreateRemoteThread(hProc, 0, 0, lpThread, lpParam, 0, 0);
}

void MemWtr::AddByteToBuffer(BYTE i)
{
	printf("Byte opcode added to buffer: 0x%02X\n", i);
	m_CurrentRemoteThreadBuffer.push_back(i);
}

void MemWtr::AddLongToBuffer(ULONG i)
{
	WORD LowHalf = LOWORD(i);
	WORD HighHalf = HIWORD(i);
	AddByteToBuffer(LOBYTE(LowHalf));
	AddByteToBuffer(HIBYTE(LowHalf));
	AddByteToBuffer(LOBYTE(HighHalf));
	AddByteToBuffer(HIBYTE(HighHalf));
}

void MemWtr::PushAllParameters(bool rtCondition)
{
	if (CurrentObjBuffer.params.size() == 0)
		return;

	std::vector<instruction_info> pushOrder;

	if (rtCondition == false)
	{
		//left -> right
		for (int i = 0; i < (int)CurrentObjBuffer.params.size(); i++)
		{
			pushOrder.push_back(CurrentObjBuffer.params.at(i));
		}
	}
	else
	{
		//right -> left
		if (CurrentObjBuffer.params.size() == 1)
		{
			pushOrder.push_back(CurrentObjBuffer.params.at(0));
		}
		else
		{
			for (int i = (int)CurrentObjBuffer.params.size() - 1; i > -1; i--){
				pushOrder.push_back(CurrentObjBuffer.params.at(i));
			}
		}
	}

	for (int z = 0; z < (int)pushOrder.size(); z++)
	{
		instruction_info * paraminfo = &pushOrder[z];

		if (paraminfo == NULL)
			continue;

		if (paraminfo->iInst == NULL)
		{
			AddByteToBuffer(0x68);	//PUSH imm32
			AddLongToBuffer(0);
			continue;
		}

		switch (paraminfo->itype)
		{
		case ITYPE_SHORT:
		case ITYPE_POINTER:
		case ITYPE_INT:
		case ITYPE_FLOAT:
		{
			if (paraminfo->iInst)
			{
				ULONG ulInst = *(PULONG)paraminfo->iInst;
				AddByteToBuffer(0x68);	//PUSH imm32
				AddLongToBuffer(ulInst);
			}
			else
			{
				AddByteToBuffer(0x68);	//PUSH imm32
				AddLongToBuffer(NULL);
			}
			break;
		}
		case ITYPE_BYTE:
		{
			BYTE BInst = *(PBYTE)paraminfo->iInst;
			AddByteToBuffer(0x6A);		//PUSH imm8
			AddByteToBuffer(BInst);
			break;
		}
		case ITYPE_BOOL:
		{
			bool bInst = *(bool *)paraminfo->iInst;
			BYTE BInst = (bInst) ? 1 : 0;
			AddByteToBuffer(0x6A);	//PUSH imm8
			AddByteToBuffer(BInst);
			break;
		}
		case ITYPE_STRING:
		{
			PCHAR strPInst = (PCHAR)paraminfo->iInst;
			PVOID AllocStr = WtrMem(strPInst, strlen(strPInst) + 1);
			if (AllocStr == NULL){ continue; }
			AddByteToBuffer(0x68);	//PUSH imm32
			AddLongToBuffer((ULONG)AllocStr);
			break;
		}
		case ITYPE_WSTRING:
		{
			PWCHAR strPInst = (PWCHAR)paraminfo->iInst;
			PVOID AllocStr = WtrMem(strPInst, (wcslen(strPInst) * 2) + 1);
			if (AllocStr == NULL){ continue; }
			AddByteToBuffer(0x68);	//PUSH imm32
			AddLongToBuffer((ULONG)AllocStr);
			break;
		}
		default:
		{
			break;
		}
		}
	}
}

PVOID MemWtr::WtrMem(PVOID pData, size_t size)
{
	PVOID pPtr = VirtualAllocEx(hProc, NULL, (ULONG)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pData != NULL)
	{
		WriteProcessMemory(hProc, pPtr, pData, size, NULL);
	}

	return pPtr;
}