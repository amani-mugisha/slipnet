#include "platform/service.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>

namespace slipnet::platform {

ServiceProbeResult probeService(
    const std::string& host,
    int port,
    const std::string& request,
    int timeoutMs
)
{
    ServiceProbeResult result;

    if (
        port < 1 ||
        port > 65535 ||
        timeoutMs <= 0
    )
    {
        return result;
    }

    SOCKET socketFd =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP
        );

    if (socketFd == INVALID_SOCKET)
    {
        return result;
    }

    sockaddr_in address{};

    address.sin_family = AF_INET;
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
        return result;
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
        return result;
    }

    auto start =
        std::chrono::steady_clock::now();

    int connection =
        connect(
            socketFd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        );

    if (connection == SOCKET_ERROR)
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
            return result;
        }

        fd_set writeSet;

        FD_ZERO(&writeSet);
        FD_SET(socketFd, &writeSet);

        timeval timeout{};

        timeout.tv_sec =
            timeoutMs / 1000;

        timeout.tv_usec =
            (timeoutMs % 1000) * 1000;

        int ready =
            select(
                0,
                nullptr,
                &writeSet,
                nullptr,
                &timeout
            );

        if (ready <= 0)
        {
            closesocket(socketFd);
            return result;
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
            return result;
        }
    }

    auto connectedAt =
        std::chrono::steady_clock::now();

    result.connected = true;

    result.latencyMs =
        std::chrono::duration<double, std::milli>(
            connectedAt - start
        ).count();

    if (!request.empty())
    {
        send(
            socketFd,
            request.data(),
            static_cast<int>(
                request.size()
            ),
            0
        );
    }

    fd_set readSet;

    FD_ZERO(&readSet);
    FD_SET(socketFd, &readSet);

    timeval timeout{};

    timeout.tv_sec =
        timeoutMs / 1000;

    timeout.tv_usec =
        (timeoutMs % 1000) * 1000;

    int ready =
        select(
            0,
            &readSet,
            nullptr,
            nullptr,
            &timeout
        );

    if (ready > 0)
    {
        char buffer[4096]{};

        const int received =
            recv(
                socketFd,
                buffer,
                sizeof(buffer) - 1,
                0
            );

        if (received > 0)
        {
            buffer[received] = '\0';

            result.response.assign(
                buffer,
                static_cast<std::size_t>(
                    received
                )
            );
        }
    }

    closesocket(socketFd);

    return result;
}

} // namespace slipnet::platform

#endif