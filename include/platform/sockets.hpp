#pragma once

#include <cstdint>

#ifdef _WIN32

    #ifndef NOMINMAX
        #define NOMINMAX
    #endif

    #include <winsock2.h>
    #include <ws2tcpip.h>

    namespace slipnet::platform {

    using SocketHandle = SOCKET;

    constexpr SocketHandle INVALID_SOCKET_HANDLE = INVALID_SOCKET;

    bool initializeSockets();
    void shutdownSockets();

    bool isValidSocket(SocketHandle socket);

    void closeSocket(SocketHandle socket);

    int getLastSocketError();

    }

#else

    #include <sys/socket.h>

    namespace slipnet::platform {

    using SocketHandle = int;

    constexpr SocketHandle INVALID_SOCKET_HANDLE = -1;

    bool initializeSockets();
    void shutdownSockets();

    bool isValidSocket(SocketHandle socket);

    void closeSocket(SocketHandle socket);

    int getLastSocketError();

    }

#endif