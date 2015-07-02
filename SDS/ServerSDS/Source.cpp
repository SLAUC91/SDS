#include "Server.h"

int main(){
	Server * TCPserver = new Server();
	TCPserver->Main();
	delete TCPserver;
	return 0;
}