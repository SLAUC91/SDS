#ifndef __Loader_H__
#define __Loader_H__

#include <Windows.h>
#include <vector>
#include <iostream>
#include <stdlib.h>
#include "MemWtr.h"
#include "Ntdll.h"
#include "MemObject.h"
#include "Process.h"

class Loader : public MemWtr, Process {
private:
	struct Module_INFO : All_SYS::LDR_DATA_TABLE_ENTRY
	{
		std::wstring			FullDllName;
		std::wstring			BaseDllName;
	};

	MemObject * ReadBinary(char *);

	LPVOID GetPtrFromRVA(DWORD, PIMAGE_NT_HEADERS, PBYTE);
	PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD, PIMAGE_NT_HEADERS);

	HMODULE GetRemoteModuleHandleA(const char *);
	FARPROC GetRemoteProcAddress(const char *, const char *);
	HMODULE LoadModuleByName(PWCHAR);

	bool FixImports(PVOID, PIMAGE_NT_HEADERS, PIMAGE_IMPORT_DESCRIPTOR);
	bool FixRelocs(PVOID, PVOID, PIMAGE_NT_HEADERS, PIMAGE_BASE_RELOCATION, UINT);
	bool MapSections(PVOID, PVOID, PIMAGE_NT_HEADERS);

	All_SYS::PLDR_DATA_TABLE_ENTRY GetNextNode(PCHAR, int);
	std::vector < Loader::Module_INFO > ListModulesA(DWORD, int, int);

public:
	Loader(std::string Proc);
	~Loader();

	//Snapshots the modules in the target process
	std::vector<Module_INFO> ModuleListStatic;

	//Snap a modules from the In-Memory Order List
	void SnapModuleList() { ModuleListStatic = ListModulesA(this->Pinfo.Process_ID, 1, 0); }

	//Helper Load Function
	HMODULE	LoadModuleByNameIntoMemoryWCHAR(PWCHAR);

	//Helper Load Function
	HMODULE LoadModuleByNameIntoMemorySTR(PCHAR);

	//Main Load Function
	HMODULE	LoadModuleFromMemory(ULONG, ULONG);
};

#endif