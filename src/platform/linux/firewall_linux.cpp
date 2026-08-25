#include "platform/firewall.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

namespace slipnet::platform
{

namespace
{

bool setNonBlocking(
    int socketFd
)
{
    const int flags =
        fcntl(
            socketFd,
            F_GETFL,
            0
        );

    if (flags < 0)
    {
        return false;
    }

    return
        fcntl(
            socketFd,
            F_SETFL,
            flags | O_NONBLOCK
        ) == 0;
}

} // namespace

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

    struct addrinfo hints{};
    struct addrinfo* addressList = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

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

    int socketFd = -1;

    for (
        auto* address = addressList;
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

        if (socketFd < 0)
        {
            continue;
        }

        if (!setNonBlocking(socketFd))
        {
            close(socketFd);
            socketFd = -1;
            continue;
        }

        const int connection =
            connect(
                socketFd,
                address->ai_addr,
                address->ai_addrlen
            );

        if (connection == 0)
        {
            result.state =
                FirewallProbeState::OPEN;

            break;
        }

        if (errno != EINPROGRESS)
        {
            if (
                errno == ECONNREFUSED
            )
            {
                result.state =
                    FirewallProbeState::CLOSED;

                result.evidence =
                    "Target actively refused the TCP connection.";

                close(socketFd);
                socketFd = -1;

                break;
            }

            close(socketFd);
            socketFd = -1;
            continue;
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
                socketFd + 1,
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

            close(socketFd);
            socketFd = -1;

            break;
        }

        if (selected < 0)
        {
            close(socketFd);
            socketFd = -1;
            continue;
        }

        int socketError = 0;
        socklen_t errorLength =
            sizeof(socketError);

        getsockopt(
            socketFd,
            SOL_SOCKET,
            SO_ERROR,
            &socketError,
            &errorLength
        );

        if (socketError == 0)
        {
            result.state =
                FirewallProbeState::OPEN;
        }
        else if (
            socketError == ECONNREFUSED
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

        close(socketFd);
        socketFd = -1;

        break;
    }

    if (socketFd >= 0)
    {
        close(socketFd);
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