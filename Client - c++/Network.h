#pragma once

#include <string>
#include <string>
#include <winsock2.h>
#include <vector>
#include <cstdint>

class Network
{
public:
    Network();
    ~Network();

    void connectToServer(const std::string& ip, unsigned short port);
	void sendAll(const std::vector<uint8_t>& data);
    std::vector<uint8_t> recvExact(size_t size);
private:
    SOCKET sock;
};