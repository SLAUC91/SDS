#include "Loader.h"

//Pietrek's Helper macro
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

Loader::Loader(std::string Proc)
{
	//Get the Process Information
	Pinfo = GetProcessInfo(Proc);

	//Open Global Handle
	HANDLE pH = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pinfo.Process_ID);

	//Set Global Target Handle
	SetProcess(pH);

	//Take snapshot of modules in the process
	SnapModuleList();
}

Loader::~Loader()
{
	//Close Global Target Handle
	CloseHandle(GetProcessHandle());
}

//Takes a wchar_t * and converts it into a String
//returns * to a ANSIstring
HMODULE	Loader::LoadModuleByNameIntoMemoryWCHAR(PWCHAR pSTR)
{
	char strANSI[MAX_PATH] = { 0 };
	wcstombs(strANSI, (PWCHAR)pSTR, MAX_PATH);

	//printf("%s\n", strANSI);
	return LoadModuleByNameIntoMemorySTR(strANSI);
}

//Read a stored on the disk into memory
//Return a buffer BYTE * to the Binary in memory
MemObject * Loader::ReadBinary(char * pSTR)
{
	if (hProc == INVALID_HANDLE_VALUE)
		return NULL;

	HANDLE hFile = CreateFileA(pSTR, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA failed!\n");
		return NULL;
	}

	printf("CreateFileA Succeeded!\n");
	ULONG uSize = NULL;
	ULONG uBytes = NULL;

	if (GetFileAttributesA(pSTR) & FILE_ATTRIBUTE_COMPRESSED)
	{
		uSize = GetCompressedFileSizeA(pSTR, NULL);
	}
	else
	{
		uSize = GetFileSize(hFile, NULL);
	}

	if (uSize == NULL)
	{
		printf("Filesize is NULL\n");
		return NULL;
	}

	printf("Filesize [0x%X]\n", uSize);

	MemObject * Mem_Obj = new MemObject(uSize);

	BOOL rfStatus = ReadFile(hFile, Mem_Obj->buffer, Mem_Obj->bSize, (LPDWORD)&uBytes, FALSE);

	CloseHandle(hFile);

	if (rfStatus == FALSE)
	{
		printf("ReadFile failed!\n");
		delete Mem_Obj;
		return NULL;
	}

	return Mem_Obj;
}

//LoadModuleFromMemory Helper function
//Creates a Binary file in memory
HMODULE Loader::LoadModuleByNameIntoMemorySTR(PCHAR pSTR)
{
	HMODULE handleRet = NULL;

	if (hProc == INVALID_HANDLE_VALUE)
		return NULL;

	//Allocate Object
	MemObject * Mem_Obj = ReadBinary(pSTR);

	printf("ReadFile Succeeded!\n");

	handleRet = LoadModuleFromMemory((ULONG)Mem_Obj->buffer, Mem_Obj->bSize);

	//dealloc
	delete Mem_Obj;
	return handleRet;
}

//Load a specifed module into a processes memory
HMODULE Loader::LoadModuleFromMemory(ULONG BaseAddress, ULONG SizeOfModule){
	if (hProc == INVALID_HANDLE_VALUE)
		return NULL;

	PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER) ((HMODULE)BaseAddress);
	PIMAGE_NT_HEADERS pNTHead = MakePtr(PIMAGE_NT_HEADERS, BaseAddress, pDosHead->e_lfanew);

	if (!pDosHead || !pNTHead || pDosHead->e_magic != IMAGE_DOS_SIGNATURE || pNTHead->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("NT and DOS headers Failed To Load!\n");
		return NULL;
	}

	printf("Loaded NT and DOS.\n");

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)GetPtrFromRVA((DWORD)(pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), pNTHead, (PBYTE)BaseAddress);

	//Check if the IMAGE_DIRECTORY is empty
	if (pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		//Check if FixImport worked
		if (!FixImports((PVOID)BaseAddress, pNTHead, pImageImportDesc))
		{
			printf("Fix Imports Failed!\n");
			return NULL;
		}
	}

	printf("Fixed Imports.\n");

	PVOID pModBase = WtrMem((PVOID)BaseAddress, SizeOfModule);

	if (pModBase == NULL)
	{
		printf("Failed To Allocate Module Space!\n");
		return NULL;
	}

	printf("Module Base: [0x%X]\n", pModBase);

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)GetPtrFromRVA((DWORD)(pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), pNTHead, (PBYTE)BaseAddress);

	//Fix Relocations
	if (pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		if (!FixRelocs((PVOID)BaseAddress, pModBase, pNTHead, pBaseRelocation, pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
		{
			printf("Fix Relocations Failed!\n");
			return NULL;
		}
	}

	printf("Fixed Relocations.\n");

	//Fix Map Sections
	if (!MapSections(pModBase, (PVOID)BaseAddress, pNTHead))
	{
		printf("Failed To Map Sections\n");
		return NULL;
	}

	printf("Mapped Sections.\n");

	ULONG pToMod = MakePtr(ULONG, pModBase, pNTHead->OptionalHeader.AddressOfEntryPoint);

	printf("Module Entry Point: [0x%X]\n", pToMod);

	//End here
	//hmod arguments
	PushInt((int)pModBase);		//Base Addr
	PushInt(1);					//DLL Attach event
	PushInt(0);					//0
	//Read upwards

	//Call Routine
	PushCall((FARPROC)pToMod);

	_thread_buffer ThreadBuffer = InitializeThreadBuffer();

	if (!WriteThreadBuffer(ThreadBuffer))
	{
		printf("Thread Creation Failed!\n");
		return NULL;
	}

	printf("Thread Created In Remote Process.\n");

	return (HMODULE) pModBase;
}

//Fixed Import Table
bool Loader::FixImports(PVOID base, PIMAGE_NT_HEADERS ntHd, PIMAGE_IMPORT_DESCRIPTOR impDesc)
{
	PCHAR pModuleName;
	while (pModuleName = (PCHAR)GetPtrFromRVA((DWORD)impDesc->Name, ntHd, (PBYTE)base))
	{
		//pModuleName = (PCHAR)GetPtrFromRVA((DWORD)impDesc->Name, ntHd, (PBYTE)base);

		//if (pModuleName == NULL)
		//{
			//printf("No Name For Unknown Module!\n");
			//return false;
		//}

		//If the library is already loaded LoadLibrary will
		//just return the handle to that module. 
		//Otherwise it will be loaded into the current process.
		HMODULE localMod = LoadLibraryA(pModuleName);

		printf("Fixing Imports For [%s]\n", pModuleName);

		//Check if the module is in the target process if not load it
		HMODULE hRemoteMod = GetRemoteModuleHandleA(pModuleName);

		if (hRemoteMod == NULL)
		{
			wchar_t strMOD[MAX_PATH] = { 0 };
			mbstowcs(strMOD, pModuleName, MAX_PATH);
			hRemoteMod = LoadModuleByName(strMOD);

			if (hRemoteMod == NULL)
			{
				printf("No Module For [%s]\n", pModuleName);
				return false;
			}
		}

		printf("Module for [%s][0x%X]\n", pModuleName, hRemoteMod);

		PIMAGE_THUNK_DATA pTrunk = (PIMAGE_THUNK_DATA)GetPtrFromRVA((DWORD)impDesc->FirstThunk, ntHd, (PBYTE)base);

		if (!pTrunk)
		{
			printf("No IMAGE_THUNK_DATA for [%s]\n", pModuleName);
			return false;
		}

		printf("IMAGE_THUNK_DATA for [%s]\n", pModuleName);

		for (; pTrunk->u1.AddressOfData != 0; pTrunk++)
		{
			PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)GetPtrFromRVA((DWORD)pTrunk->u1.AddressOfData, ntHd, (PBYTE)base);

			if (pIBN == NULL)
			{
				printf("No IMAGE_IMPORT_BY_NAME for [0x%X]\n", pTrunk->u1.AddressOfData);
				return false;
			}

			printf("IMAGE_IMPORT_BY_NAME For [0x%X]\n", pTrunk->u1.AddressOfData);

			PCHAR pImportName = (PCHAR)pIBN->Name;

			if (pImportName == NULL)
			{
				printf("No Import Name for [0x%X]\n", pTrunk->u1.AddressOfData);
				return false;
			}

			printf("Import Name For [%s][0x%X]\n", pImportName, pTrunk->u1.AddressOfData);

			FARPROC pRemoteFunc = GetRemoteProcAddress(pModuleName, pImportName);

			if (pRemoteFunc == NULL)
			{
				printf("No Import Address For [%s]\n", pImportName);
				return false;
			}

			printf("Import Address For [%s][0x%X]\n", pImportName, pRemoteFunc);

			pTrunk->u1.Function = (DWORD)pRemoteFunc;
		}

		impDesc++;
	}

	return true;
}

//Pietrek's Function
PIMAGE_SECTION_HEADER Loader::GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	UINT i;

	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
	{
		DWORD size = section->Misc.VirtualSize;
		if (size == NULL)
		{
			size = section->SizeOfRawData;
		}

		if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
		{
			return section;
		}
	}
	return NULL;
}

//Pietrek's Function
LPVOID Loader::GetPtrFromRVA(DWORD rva, PIMAGE_NT_HEADERS pNTHeader, PBYTE imageBase)
{
	PIMAGE_SECTION_HEADER pSectionHdr;
	INT delta;
	pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);

	if (!pSectionHdr)
		return 0;

	delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
	return (PVOID)(imageBase + rva - delta);
}

HMODULE Loader::GetRemoteModuleHandleA(const char * strModule)
{
	HMODULE pMod;
	//ModuleListStatic = ListModulesA((DWORD)hProc, 0, 0);
	for (ULONG i = 0; i < ModuleListStatic.size(); i++){
		const wchar_t * wstr = (ModuleListStatic[i].BaseDllName).c_str();
		char str[MAX_PATH] = { 0 };
		wcstombs(str, (PWCHAR)wstr, MAX_PATH);

		//_stricmp - compares the strings case insensitive
		if (_stricmp(strModule, str) == 0){
			GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPSTR)ModuleListStatic[i].BaseAddress, &pMod);
			return pMod;
		}

	}
	return NULL;
}

//LoadLibrary in the target process if the module is not there 
//TODO: Change this to manually map needed modules
HMODULE Loader::LoadModuleByName(PWCHAR pSTR)
{
	char pModule[MAX_PATH] = { 0 };
	wcstombs(pModule, pSTR, MAX_PATH);

	HMODULE modCheck = GetRemoteModuleHandleA(pModule);

	//Module Found Check
	if (modCheck) { return modCheck; }

	if (pSTR == NULL) { return NULL; }

	FARPROC pFunc = GetRemoteProcAddress("kernel32.dll", "LoadLibraryW");

	if (pFunc == NULL) { return NULL; }

	PushUNICODEString(pSTR);
	PushCall(pFunc);

	_thread_buffer rtb = InitializeThreadBuffer();

	if (WriteThreadBuffer(rtb) == false) { return NULL; }

	//Snap Module in the current PEB as new mod added
	SnapModuleList();

	return GetRemoteModuleHandleA(pModule);
}

FARPROC Loader::GetRemoteProcAddress(const char * pStrMod, const char * pFunc)
{
	//Can do this in a cleaner way without having to load anything into this process
	//But this is easier to code because of the way modules work in windows
	ULONG LocalMod = (ULONG)GetModuleHandleA(pStrMod);
	ULONG LocalFunc = (ULONG)GetProcAddress((HMODULE)LocalMod, pFunc);
	ULONG RemoteMod = (ULONG)GetRemoteModuleHandleA(pStrMod);
	return (FARPROC)((LocalFunc - LocalMod) + RemoteMod);
}

//Fix the Relocations of PE
bool Loader::FixRelocs(PVOID pBaseAddr, PVOID prBase, PIMAGE_NT_HEADERS pNTHeader, PIMAGE_BASE_RELOCATION pRealloc, UINT size)
{
	ULONG ImageBase = pNTHeader->OptionalHeader.ImageBase;
	UINT nBytes = 0;
	ULONG delta = (ULONG)((DWORD_PTR)(prBase)-(DWORD_PTR)(ImageBase));

	for (;;)
	{
		PULONG locBase = (PULONG)GetPtrFromRVA((DWORD)(pRealloc->VirtualAddress), pNTHeader, (PBYTE)pBaseAddr);
		UINT numRelocs = (pRealloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		if (nBytes >= size)
			break;

		PUSHORT locData = MakePtr(PUSHORT, pRealloc, sizeof(IMAGE_BASE_RELOCATION));

		for (UINT i = 0; i < numRelocs; i++)
		{
			if (((*locData >> 12) & IMAGE_REL_BASED_HIGHLOW))
				*MakePtr(PULONG, locBase, (*locData & 0x0FFF)) += delta;

			locData++;
		}

		nBytes += pRealloc->SizeOfBlock;
		pRealloc = (PIMAGE_BASE_RELOCATION)locData;
	}

	return true;
}

//Fix the Map Section of PE
bool Loader::MapSections(PVOID pModBase, PVOID pBaseAddr, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER header = IMAGE_FIRST_SECTION(pNTHeader);
	UINT nBytes = 0;
	UINT virtualSize = 0;
	UINT n = 0;

	for (UINT i = 0; pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (nBytes >= pNTHeader->OptionalHeader.SizeOfImage)
			break;

		WriteProcessMemory(GetProcessHandle(), MakePtr(LPVOID, pModBase, header->VirtualAddress), MakePtr(LPCVOID, pBaseAddr, header->PointerToRawData), header->SizeOfRawData, (LPDWORD)&n);

		virtualSize = header->VirtualAddress;

		header++;

		virtualSize = header->VirtualAddress - virtualSize;

		nBytes += virtualSize;

		MEMORY_BASIC_INFORMATION mbi;

		VirtualQueryEx(GetProcessHandle(), MakePtr(LPVOID, pModBase, header->VirtualAddress), &mbi, sizeof(mbi));

		VirtualProtectEx(GetProcessHandle(), mbi.BaseAddress, mbi.RegionSize, header->Characteristics & 0x00FFFFFF, NULL);

		FlushInstructionCache(GetProcessHandle(), mbi.BaseAddress, mbi.RegionSize);
	}

	return true;
}

//Helper function to calculate the address of the next node
All_SYS::PLDR_DATA_TABLE_ENTRY Loader::GetNextNode(PCHAR nNode, int Offset){
#ifdef _WIN64
	nNode -= sizeof(LIST_ENTRY64) * Offset;
#else
	nNode -= sizeof(LIST_ENTRY) * Offset;
#endif
	return (All_SYS::PLDR_DATA_TABLE_ENTRY)nNode;
}

//List the Modules using the target processes PEB x64-x32
std::vector < Loader::Module_INFO > Loader::ListModulesA(DWORD PID, int ListType, int Order){
	Module_INFO MD;
	std::vector < Module_INFO > ListOfMods;
	pNtQueryInformationProcess NtQIP;
	NTSTATUS status;
	std::wstring BaseDllName;
	std::wstring FullDllName;

	if (ListType > 2 || ListType < 0 || Order > 1 || Order < 0){
		return ListOfMods;
	}

	PROCESS_BASIC_INFORMATION PBI = { 0 };
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
	NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");
	status = NT_SUCCESS(NtQIP(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), NULL));

	if (status)
	{
		All_SYS::PEB_LDR_DATA LdrData;
		All_SYS::LDR_DATA_TABLE_ENTRY LdrModule;
		All_SYS::PPEB_LDR_DATA pLdrData = nullptr;
		PBYTE address = nullptr;

		PBYTE LdrDataOffset = (PBYTE)(PBI.PebBaseAddress) + offsetof(struct All_SYS::_PEB, LoaderData);
		ReadProcessMemory(ProcessHandle, LdrDataOffset, &pLdrData, sizeof(All_SYS::PPEB_LDR_DATA), NULL);
		ReadProcessMemory(ProcessHandle, pLdrData, &LdrData, sizeof(All_SYS::PEB_LDR_DATA), NULL);

		if (Order == 0){
			if (ListType == 0)
				address = (PBYTE)LdrData.InLoadOrderModuleList.Flink;
			else if (ListType == 1)
				address = (PBYTE)LdrData.InMemoryOrderModuleList.Flink;
			else if (ListType == 2)
				address = (PBYTE)LdrData.InInitializationOrderModuleList.Flink;
		}
		else{
			if (ListType == 0)
				address = (PBYTE)LdrData.InLoadOrderModuleList.Blink;
			else if (ListType == 1)
				address = (PBYTE)LdrData.InMemoryOrderModuleList.Blink;
			else if (ListType == 2)
				address = (PBYTE)LdrData.InInitializationOrderModuleList.Blink;
		}

#ifdef _WIN64
		address -= sizeof(LIST_ENTRY64)*ListType;
#else
		address -= sizeof(LIST_ENTRY)*ListType;
#endif

		All_SYS::PLDR_DATA_TABLE_ENTRY Head = (All_SYS::PLDR_DATA_TABLE_ENTRY)address;
		All_SYS::PLDR_DATA_TABLE_ENTRY Node = Head;

		do
		{
			BOOL status1 = ReadProcessMemory(ProcessHandle, Node, &LdrModule, sizeof(All_SYS::LDR_DATA_TABLE_ENTRY), NULL);
			if (status1)
			{

				BaseDllName = std::wstring(LdrModule.BaseDllName.Length / sizeof(WCHAR), 0);
				FullDllName = std::wstring(LdrModule.FullDllName.Length / sizeof(WCHAR), 0);
				ReadProcessMemory(ProcessHandle, LdrModule.BaseDllName.Buffer, &BaseDllName[0], LdrModule.BaseDllName.Length, NULL);
				ReadProcessMemory(ProcessHandle, LdrModule.FullDllName.Buffer, &FullDllName[0], LdrModule.FullDllName.Length, NULL);

				BaseDllName.push_back('\0');
				FullDllName.push_back('\0');

				MD.BaseAddress = LdrModule.BaseAddress;
				MD.EntryPoint = LdrModule.EntryPoint;
				MD.SizeOfImage = LdrModule.SizeOfImage;
				MD.Flags = LdrModule.Flags;
				MD.LoadCount = LdrModule.LoadCount;
				MD.TlsIndex = LdrModule.TlsIndex;
				MD.TimeDateStamp = LdrModule.TimeDateStamp;
				MD.FullDllName = FullDllName;
				MD.BaseDllName = BaseDllName;

				if (LdrModule.BaseAddress != 0)
				{
					ListOfMods.push_back(MD);
				}

				else{
					break;
				}
			}

			if (Order == 0){
				if (ListType == 0)
					Node = GetNextNode((PCHAR)LdrModule.InLoadOrderModuleList.Flink, ListType);
				else if (ListType == 1)
					Node = GetNextNode((PCHAR)LdrModule.InMemoryOrderModuleList.Flink, ListType);
				else if (ListType == 2)
					Node = GetNextNode((PCHAR)LdrModule.InInitializationOrderModuleList.Flink, ListType);
			}
			else{
				if (ListType == 0)
					Node = GetNextNode((PCHAR)LdrModule.InLoadOrderModuleList.Blink, ListType);
				else if (ListType == 1)
					Node = GetNextNode((PCHAR)LdrModule.InMemoryOrderModuleList.Blink, ListType);
				else if (ListType == 2)
					Node = GetNextNode((PCHAR)LdrModule.InInitializationOrderModuleList.Blink, ListType);
			}

		} while (Head != Node);
	}

	CloseHandle(ProcessHandle);
	return ListOfMods;
}