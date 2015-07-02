#ifndef __Process_H__
#define __Process_H__

#include <string>
#include <vector>
#include <Windows.h>
#include "Ntdll.h"

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

class Process{
private:

public:

	struct Process_INFO{
		DWORD Process_ID = 0;
		std::string Process_Name = "";
		std::string Create_Time = "";
		ULONG HandleCount = 0;
		ULONG ModuleCount = 0;
		ULONG ThreadCount = 0;
	}Pinfo;

	Process_INFO GetProcessInfo(std::string & PN);
};

#endif