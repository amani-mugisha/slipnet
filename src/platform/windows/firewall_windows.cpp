#include "platform/firewall.hpp"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <string>

#pragma comment(lib, "ws2_32.lib")

namespace slipnet::platform
{

FirewallProbeResult probeTCP(
    const std::string& host,
    int port,
    int timeoutMs
)
{
    FirewallProbeResult result;

    result.port = port;

    if (
        port < 1 ||
        port > 65535
    )
    {
        result.evidence =
            "Invalid TCP port.";

        return result;
    }

    const auto start =
        std::chrono::steady_clock::now();

    addrinfo hints{};
    addrinfo* addressList = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string portText =
        std::to_string(port);

    const int lookup =
        getaddrinfo(
            host.c_str(),
            portText.c_str(),
            &hints,
            &addressList
        );

    if (
        lookup != 0 ||
        addressList == nullptr
    )
    {
        result.evidence =
            "Unable to resolve the target address.";

        return result;
    }

    SOCKET socketFd =
        INVALID_SOCKET;

    for (
        addrinfo* address = addressList;
        address != nullptr;
        address = address->ai_next
    )
    {
        socketFd =
            socket(
                address->ai_family,
                address->ai_socktype,
                address->ai_protocol
            );

        if (
            socketFd ==
            INVALID_SOCKET
        )
        {
            continue;
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
            socketFd = INVALID_SOCKET;
            continue;
        }

        const int connection =
            connect(
                socketFd,
                address->ai_addr,
                static_cast<int>(
                    address->ai_addrlen
                )
            );

        if (connection == 0)
        {
            result.state =
                FirewallProbeState::OPEN;

            closesocket(socketFd);
            socketFd = INVALID_SOCKET;

            break;
        }

        const int error =
            WSAGetLastError();

        if (
            error != WSAEWOULDBLOCK &&
            error != WSAEINPROGRESS
        )
        {
            if (
                error == WSAECONNREFUSED
            )
            {
                result.state =
                    FirewallProbeState::CLOSED;

                result.evidence =
                    "Target actively refused the TCP connection.";
            }

            closesocket(socketFd);
            socketFd = INVALID_SOCKET;

            break;
        }

        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(socketFd, &writeSet);

        timeval timeout{};

        timeout.tv_sec =
            timeoutMs / 1000;

        timeout.tv_usec =
            (timeoutMs % 1000) * 1000;

        const int selected =
            select(
                0,
                nullptr,
                &writeSet,
                nullptr,
                &timeout
            );

        if (selected == 0)
        {
            result.state =
                FirewallProbeState::FILTERED;

            result.evidence =
                "Connection attempt timed out without "
                "an explicit TCP response.";
        }
        else if (selected < 0)
        {
            result.state =
                FirewallProbeState::UNKNOWN;

            result.evidence =
                "Unable to determine TCP connection state.";
        }
        else
        {
            int socketError = 0;
            int errorLength =
                sizeof(socketError);

            getsockopt(
                socketFd,
                SOL_SOCKET,
                SO_ERROR,
                reinterpret_cast<char*>(
                    &socketError
                ),
                &errorLength
            );

            if (socketError == 0)
            {
                result.state =
                    FirewallProbeState::OPEN;
            }
            else if (
                socketError ==
                WSAECONNREFUSED
            )
            {
                result.state =
                    FirewallProbeState::CLOSED;

                result.evidence =
                    "Target actively refused the TCP connection.";
            }
            else
            {
                result.state =
                    FirewallProbeState::UNKNOWN;

                result.evidence =
                    "TCP connection failed without sufficient "
                    "evidence for a definitive classification.";
            }
        }

        closesocket(socketFd);
        socketFd = INVALID_SOCKET;

        break;
    }

    if (
        socketFd != INVALID_SOCKET
    )
    {
        closesocket(socketFd);
    }

    freeaddrinfo(addressList);

    const auto end =
        std::chrono::steady_clock::now();

    result.latencyMs =
        static_cast<int>(
            std::chrono::duration_cast<
                std::chrono::milliseconds
            >(end - start).count()
        );

    if (
        result.state ==
        FirewallProbeState::OPEN
    )
    {
        result.evidence =
            "TCP connection established successfully.";
    }

    if (
        result.state ==
        FirewallProbeState::UNKNOWN &&
        result.evidence.empty()
    )
    {
        result.evidence =
            "Insufficient evidence for classification.";
    }

    return result;
}

} // namespace slipnet::platform

#endif