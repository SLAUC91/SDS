#ifndef __Client_H__
#define __Client_H__

#pragma once
#pragma comment(lib, "Ws2_32.lib");

#include <sdkddkver.h>
#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include "MemObject.h"

#define Socket_V2 0x0202

class Client{
private:

public:
	Client();
	~Client();

	MemObject * RecvBinary();
};

#endif