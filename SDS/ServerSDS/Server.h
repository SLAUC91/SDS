#ifndef __Server_H__
#define __Server_H__

#pragma comment(lib, "Ws2_32.lib")

#include <sdkddkver.h>
#include <conio.h>
#include <stdio.h>

//socket
#include <WinSock2.h>
#include <Windows.h>
#include <iostream>

#include "LoacReader.h"

#define Socket_V2 0x0202

class Server : public LoadReader{
private:

	SOCKET serverSock;

public:
	Server();
	~Server();

	void Main();
	void ClientThread(LPVOID);
	void ServerThread();
};

#endif