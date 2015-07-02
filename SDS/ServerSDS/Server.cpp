#include "Server.h"
#include <thread>

Server::Server(){

}

Server::~Server(){

}

void CreateCon(){

}

void Server::ClientThread(LPVOID pParam)
{
	long Status;
	SOCKET clientSock = (SOCKET)pParam;

	MemObject * Data = NULL;
	
	//The dll on the hard drive - Server use
	Data = ReadBinaryB("test_module.dll");

	//mod size buffer
	char ulongtoByte[10];
	char * sizeOfMod = NULL;
	sizeOfMod = _ultoa(Data->bSize, ulongtoByte, 10);
	
	//Send the module size 
	Status = send(clientSock, sizeOfMod, sizeof(sizeOfMod) + 1, NULL);

	//Send the module data
	for (ULONG i = 0; i < Data->bSize; i++){
		CHAR bit = (CHAR)Data->buffer[i];
		Status = send(clientSock, &bit, sizeof(BYTE), NULL);
		//printf("sent: %c %d\n", Data->buffer[i], i);
	}

	//cleanup
	closesocket(clientSock);
	return;
	
}

void Server::ServerThread(){
	printf("ServerThread");

	long Status;
	WSADATA WinSocketData;
	WORD DLLVERSION;
	DLLVERSION = MAKEWORD(1, 0);

	Status = WSAStartup(DLLVERSION, &WinSocketData);

	//socket creation
	SOCKADDR_IN Address;
	int Addr_Size = sizeof(Address);

	Address.sin_family = AF_INET;
	Address.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	Address.sin_port = htons((USHORT)12345);
	serverSock = socket(AF_INET, SOCK_STREAM, NULL);

	if (serverSock == INVALID_SOCKET)
	{
		printf("Failed To Open Socket!\n");
		return;
	}

	if (bind(serverSock, (PSOCKADDR)&Address, sizeof(Address)) != 0)
	{
		printf("Failed To Bind!\n");
		return;
	}

	if (listen(serverSock, SOMAXCONN) != 0)
	{
		printf("Failed To Listen!\n");
		return;
	}

	SOCKET clientSock;

	for (;;)
	{
		std::cout << "Server: Running..." << std::endl;
		clientSock = accept(serverSock, (PSOCKADDR)&Address, &Addr_Size);
		std::thread T2(&Server::ClientThread, this, (LPVOID) clientSock);
		T2.detach();
	}

	return;
}

void Server::Main(){
	std::thread T1(&Server::ServerThread, this);
	while (_getch() != 27);	//exit - ESC
	closesocket(serverSock);
	WSACleanup();
}