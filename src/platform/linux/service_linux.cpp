#include "platform/service.hpp"

#ifndef _WIN32

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

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

    int socketFd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (socketFd < 0)
    {
        return result;
    }

    sockaddr_in address{};

    address.sin_family = AF_INET;
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
        return result;
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
        return result;
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

    if (
        connection < 0 &&
        errno != EINPROGRESS &&
        errno != EWOULDBLOCK
    )
    {
        close(socketFd);
        return result;
    }

    if (connection != 0)
    {
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
                socketFd + 1,
                nullptr,
                &writeSet,
                nullptr,
                &timeout
            );

        if (ready <= 0)
        {
            close(socketFd);
            return result;
        }

        int socketError = 0;
        socklen_t length =
            sizeof(socketError);

        if (
            getsockopt(
                socketFd,
                SOL_SOCKET,
                SO_ERROR,
                &socketError,
                &length
            ) != 0 ||
            socketError != 0
        )
        {
            close(socketFd);
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

    /*
     * Send an application-level request
     * when one is provided.
     */
    if (!request.empty())
    {
        send(
            socketFd,
            request.data(),
            request.size(),
            0
        );
    }

    /*
     * Wait for a response.
     */
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
            socketFd + 1,
            &readSet,
            nullptr,
            nullptr,
            &timeout
        );

    if (ready > 0)
    {
        char buffer[4096]{};

        const ssize_t received =
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

    close(socketFd);

    return result;
}

} // namespace slipnet::platform

#endif