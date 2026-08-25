#include "platform/tcp.hpp"

#ifndef _WIN32

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace slipnet::platform
{

namespace
{

bool waitForSocket(
    int socketFd,
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
            socketFd + 1,
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

    int socketFd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (socketFd < 0)
    {
        return connection;
    }

    sockaddr_in address{};

    address.sin_family =
        AF_INET;

    address.sin_port =
        htons(
            static_cast<uint16_t>(port)
        );

    if (
        inet_pton(
            AF_INET,
            host.c_str(),
            &address.sin_addr
        ) != 1
    )
    {
        close(socketFd);
        return connection;
    }

    int flags =
        fcntl(
            socketFd,
            F_GETFL,
            0
        );

    if (flags < 0)
    {
        close(socketFd);
        return connection;
    }

    if (
        fcntl(
            socketFd,
            F_SETFL,
            flags | O_NONBLOCK
        ) < 0
    )
    {
        close(socketFd);
        return connection;
    }

    int result =
        connect(
            socketFd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        );

    if (result < 0)
    {
        if (!waitForSocket(
                socketFd,
                true,
                timeoutMs
            ))
        {
            close(socketFd);
            return connection;
        }

        int error = 0;
        socklen_t length =
            sizeof(error);

        if (
            getsockopt(
                socketFd,
                SOL_SOCKET,
                SO_ERROR,
                &error,
                &length
            ) != 0 ||
            error != 0
        )
        {
            close(socketFd);
            return connection;
        }
    }

    connection.handle =
        socketFd;

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

    const char* buffer =
        data.data();

    std::size_t remaining =
        data.size();

    while (remaining > 0)
    {
        ssize_t sent =
            send(
                connection.handle,
                buffer,
                remaining,
                0
            );

        if (sent <= 0)
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

    if (
        !waitForSocket(
            connection.handle,
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

    ssize_t received =
        recv(
            connection.handle,
            result.data(),
            result.size(),
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
        close(
            connection.handle
        );
    }

    connection.handle = -1;
    connection.valid = false;
}

} // namespace slipnet::platform

#endif