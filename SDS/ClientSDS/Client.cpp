#include "Client.h"
#include  <stdlib.h>
using namespace std;

Client::Client(){

}

Client::~Client(){

}

MemObject * Client::RecvBinary(){

	long Status;
	WSAData WinSocketData;
	WORD DLLVersion;
	DLLVersion = MAKEWORD(1, 0);
	Status = WSAStartup(DLLVersion, &WinSocketData);

	string Response;
	MemObject * Data = NULL;

	SOCKADDR_IN Address;

	SOCKET sock;
	sock = socket(AF_INET, SOCK_STREAM, NULL);

	Address.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	Address.sin_family = AF_INET;
	Address.sin_port = htons(12345);

	cout << "Connect [y/n]" << endl;
	cin >> Response;

	if (Response == "n"){
		cout << "QUIT\n";
		return NULL;
	}
	else if (Response == "y"){
		connect(sock, (PSOCKADDR)&Address, sizeof(Address));

		char MSG[200];

		//Read the ULONG - size of Memobj
		Status = recv(sock, MSG, sizeof(MSG), NULL);

		//convert String to ULONG
		ULONG sizeOfMod = strtoul(MSG, NULL, 10);

		printf("Filesize [0x%X]\n", sizeOfMod);

		//Create our memobject to store our buffer
		Data = new MemObject(sizeOfMod);

		int index = 0;	//Index into our memory object buffer

		//On The Recv Read Only A Byte
		while ((Status = recv(sock, MSG, sizeof(BYTE), NULL)) > 0){
			Data->buffer[index] = (BYTE)MSG[0];	//Read only the first byte
			//printf("recv: %c %d\n", Data->buffer[index], index);
			index++;
		}

		closesocket(sock);
		WSACleanup();
		return Data;
	}
	else{
		cout << "ERROR" << endl;
		return NULL;
	}

	//return Data;
}