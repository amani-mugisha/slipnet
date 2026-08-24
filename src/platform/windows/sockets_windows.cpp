#include "platform/sockets.hpp"

#ifdef _WIN32

namespace slipnet::platform {

bool initializeSockets()
{
    WSADATA wsaData{};

    const int result = WSAStartup(
        MAKEWORD(2, 2),
        &wsaData
    );

    return result == 0;
}

void shutdownSockets()
{
    WSACleanup();
}

bool isValidSocket(SocketHandle socket)
{
    return socket != INVALID_SOCKET;
}

void closeSocket(SocketHandle socket)
{
    if (isValidSocket(socket)) {
        ::closesocket(socket);
    }
}

int getLastSocketError()
{
    return WSAGetLastError();
}

} // namespace slipnet::platform

#endif