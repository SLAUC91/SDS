#include "LoacReader.h"
#include <iostream>

//Read Binary Into Memory
MemObject * LoadReader::ReadBinaryB(PCHAR pSTR){
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

	//printf("File Read [0x%X]\n", uSize);

	CloseHandle(hFile);

	if (rfStatus == FALSE)
	{
		printf("ReadFile failed!\n");
		delete Mem_Obj;
		return NULL;
	}

	return Mem_Obj;
}