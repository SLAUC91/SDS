#include "Process.h"
//#include <iostream> //Debugging

#pragma optimize("", off)
//Get the Process Information
Process::Process_INFO Process::GetProcessInfo(std::string & PN){
	PVOID buffer = NULL;
	PSYSTEM_PROCESS_INFO inf = NULL;
	LPWSTR ProcNAME;

	//convert CHAR to WCHAR
	/*int nChars = MultiByteToWideChar(CP_ACP, 0, PN, -1, NULL, 0);
	LPWSTR P1 = new WCHAR[nChars];	//Release this at some point
	MultiByteToWideChar(CP_ACP, 0, PN, -1, (LPWSTR)P1, nChars);
	//delete[] P1;
	*/

	ULONG buffer_size = 512 * 512;

	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	_ntQSI fpQSI = (_ntQSI)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");


	buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (buffer == NULL){
		return Pinfo;
	}

	Status = fpQSI((SYSTEM_INFORMATION_CLASS)All_SYS::SystemExtendedProcessInformation, buffer, buffer_size, NULL);

	//if buffer is too small double size
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		buffer_size *= 2;
	}

	else if (!NT_SUCCESS(Status)) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return Pinfo;
	}

	else{
		inf = (PSYSTEM_PROCESS_INFO)buffer;

		while (inf) {
			ProcNAME = inf->ImageName.Buffer;

			if (inf->ImageName.Buffer != nullptr){

				//List of all the process id on the current system
				if (inf->UniqueProcessId > 0){
					//System_PID_List.push_back(inf->UniqueProcessId);
				}

				//WinAPI - Converts a Wide Char to multibyte
				int nLen = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)ProcNAME, -1, NULL, NULL, NULL, NULL);
				LPSTR P1 = new CHAR[nLen];
				WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)ProcNAME, -1, P1, nLen, NULL, NULL);
				std::string ProcessName(P1);
				delete[] P1;
				//std::cout << P1 << std::endl;
				//if (strcmp(PN, ProcessName) == 0){
				if (PN.compare(ProcessName) == 0){
					Pinfo.Process_ID = (DWORD)inf->UniqueProcessId;

					Pinfo.Process_Name = ProcessName;
					CHAR szTemp[MAX_PATH] = { 0 };
					sprintf(szTemp, "%I64d", (inf->CreateTime).QuadPart);
					Pinfo.Create_Time = szTemp;
					Pinfo.ThreadCount = inf->NumberOfThreads;
					Pinfo.HandleCount = inf->HandleCount;

					/*FILETIME ft;
					SYSTEMTIME st;
					GetSystemTime(&st);
					SystemTimeToFileTime(&st, &ft);
					LARGE_INTEGER CT = inf->CreateTime;
					CHAR szTemp[MAX_PATH] = { 0 };
					CHAR szTemp1[MAX_PATH] = { 0 };
					sprintf(szTemp, "%I64d", CT.QuadPart);
					sprintf(szTemp1, "%I64d", ft);
					std::cout << szTemp << std::endl;
					std::cout << szTemp1 << std::endl;*/
					//std::cout << PID << std::endl;
					//delete[] P1;

					//return Pinfo;
				}
				//delete[] P1;


				/*//Testing stuff
				if (wcscmp(P1, ProcNAME) == 0){
				PID = (DWORD)inf->UniqueProcessId;
				delete[] P1;
				std::cout << PID << std::endl;
				return PID;
				}*/

			}

			if (!inf->NextEntryOffset)
				break;

			inf = (PSYSTEM_PROCESS_INFO)((LPBYTE)inf + inf->NextEntryOffset);
		}

		if (buffer) VirtualFree(buffer, NULL, MEM_RELEASE);
	}

	return Pinfo;
}
#pragma optimize("", on)