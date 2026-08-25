#include "platform/tcp.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>

namespace slipnet::platform
{

namespace
{

bool initialized()
{
    static bool ready = []()
    {
        WSADATA data{};

        return
            WSAStartup(
                MAKEWORD(2, 2),
                &data
            ) == 0;
    }();

    return ready;
}

bool waitForSocket(
    SOCKET socketFd,
    bool writeReady,
    int timeoutMs
)
{
    fd_set set;

    FD_ZERO(&set);
    FD_SET(socketFd, &set);

    timeval timeout{};

    timeout.tv_sec =
        timeoutMs / 1000;

    timeout.tv_usec =
        (timeoutMs % 1000) * 1000;

    int result =
        select(
            0,
            writeReady ? nullptr : &set,
            writeReady ? &set : nullptr,
            nullptr,
            &timeout
        );

    return result > 0;
}

} // namespace


TcpConnection tcpConnect(
    const std::string& host,
    int port,
    int timeoutMs
)
{
    TcpConnection connection;

    if (!initialized())
    {
        return connection;
    }

    SOCKET socketFd =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP
        );

    if (socketFd == INVALID_SOCKET)
    {
        return connection;
    }

    sockaddr_in address{};

    address.sin_family =
        AF_INET;

    address.sin_port =
        htons(
            static_cast<u_short>(port)
        );

    if (
        inet_pton(
            AF_INET,
            host.c_str(),
            &address.sin_addr
        ) != 1
    )
    {
        closesocket(socketFd);
        return connection;
    }

    u_long nonBlocking = 1;

    if (
        ioctlsocket(
            socketFd,
            FIONBIO,
            &nonBlocking
        ) != 0
    )
    {
        closesocket(socketFd);
        return connection;
    }

    int result =
        connect(
            socketFd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        );

    if (result == SOCKET_ERROR)
    {
        int error =
            WSAGetLastError();

        if (
            error != WSAEWOULDBLOCK &&
            error != WSAEINPROGRESS &&
            error != WSAEALREADY
        )
        {
            closesocket(socketFd);
            return connection;
        }

        if (
            !waitForSocket(
                socketFd,
                true,
                timeoutMs
            )
        )
        {
            closesocket(socketFd);
            return connection;
        }

        int socketError = 0;
        int length =
            sizeof(socketError);

        if (
            getsockopt(
                socketFd,
                SOL_SOCKET,
                SO_ERROR,
                reinterpret_cast<char*>(
                    &socketError
                ),
                &length
            ) != 0 ||
            socketError != 0
        )
        {
            closesocket(socketFd);
            return connection;
        }
    }

    connection.handle =
        static_cast<int>(socketFd);

    connection.valid =
        true;

    return connection;
}


bool tcpSend(
    TcpConnection& connection,
    const std::string& data
)
{
    if (!connection.valid)
    {
        return false;
    }

    SOCKET socketFd =
        static_cast<SOCKET>(
            connection.handle
        );

    const char* buffer =
        data.data();

    std::size_t remaining =
        data.size();

    while (remaining > 0)
    {
        int sent =
            send(
                socketFd,
                buffer,
                static_cast<int>(remaining),
                0
            );

        if (sent == SOCKET_ERROR)
        {
            return false;
        }

        buffer += sent;

        remaining -=
            static_cast<std::size_t>(sent);
    }

    return true;
}


std::string tcpReceive(
    TcpConnection& connection,
    int maxBytes
)
{
    if (
        !connection.valid ||
        maxBytes <= 0
    )
    {
        return {};
    }

    SOCKET socketFd =
        static_cast<SOCKET>(
            connection.handle
        );

    if (
        !waitForSocket(
            socketFd,
            false,
            2000
        )
    )
    {
        return {};
    }

    std::string result;

    result.resize(
        static_cast<std::size_t>(maxBytes)
    );

    int received =
        recv(
            socketFd,
            result.data(),
            maxBytes,
            0
        );

    if (received <= 0)
    {
        return {};
    }

    result.resize(
        static_cast<std::size_t>(received)
    );

    return result;
}


void tcpClose(
    TcpConnection& connection
)
{
    if (connection.valid)
    {
        closesocket(
            static_cast<SOCKET>(
                connection.handle
            )
        );
    }

    connection.handle = -1;
    connection.valid = false;
}

} // namespace slipnet::platform

#endif