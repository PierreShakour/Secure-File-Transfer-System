#include "Network.h"

#include <ws2tcpip.h>
#include <stdexcept>

#pragma comment(lib, "Ws2_32.lib")


Network::Network() : sock(INVALID_SOCKET)
{
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        throw std::runtime_error("WSAStartup failed");
    }
}

void Network::connectToServer(const std::string& ip, unsigned short port)
{
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock == INVALID_SOCKET)
    {
        throw std::runtime_error("Socket creation failed");
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr) != 1)
    {
        closesocket(sock);
        sock = INVALID_SOCKET;

        throw std::runtime_error("Invalid IP address");
    }

    if (connect(
        sock,
        reinterpret_cast<sockaddr*>(&serverAddr),
        sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(sock);
        sock = INVALID_SOCKET;

        throw std::runtime_error("Connection failed");
    }
}

// Send all data in the vector, handling partial sends
void Network::sendAll(const std::vector<uint8_t>& data)
{
	// number of bytes sent so far
	size_t totalSent = 0;
    while (totalSent < data.size()) {
		// sent will be the number of bytes sent in this iteration
		// Argument 1: the socket to send data on , Argument 2: pointer to the data to send(re interpreted as a char pointer)
        // Argument 3: number of bytes to send, Argument 4: flags (0 for no flags)
		int sent = send(sock, reinterpret_cast<const char*>(data.data() + totalSent), data.size() - totalSent, 0);
		if (sent == SOCKET_ERROR) {
			throw std::runtime_error("Send failed");
		}
        if (sent == 0)
        {
            throw std::runtime_error("Connection closed while sending");
        }
		totalSent += sent;
    }
}

std::vector<uint8_t> Network::recvExact(size_t size)
{
    std::vector<uint8_t> data(size);
    size_t totalReceived = 0;

    while (totalReceived < size)
    {
        int received = recv(sock, reinterpret_cast<char*>(data.data() + totalReceived), static_cast<int>(size - totalReceived), 0);
        if (received == SOCKET_ERROR)
        {
            throw std::runtime_error("Receive failed");
        }
        if (received == 0)
        {
            throw std::runtime_error("Connection closed while receiving");
        }
        totalReceived += received;
    }

    return data;
}

Network::~Network()
{
    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
    }

    WSACleanup();
}

