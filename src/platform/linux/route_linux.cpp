#include "platform/route.hpp"

#ifndef _WIN32

#include <arpa/inet.h>

#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace slipnet::platform
{

namespace
{

std::string addressToString(
    const sockaddr* address
)
{
    if (address == nullptr)
    {
        return {};
    }

    if (
        address->sa_family != AF_INET
    )
    {
        return {};
    }

    char buffer[INET_ADDRSTRLEN]{};

    const auto* ipv4 =
        reinterpret_cast<const sockaddr_in*>(
            address
        );

    if (
        inet_ntop(
            AF_INET,
            &ipv4->sin_addr,
            buffer,
            sizeof(buffer)
        ) == nullptr
    )
    {
        return {};
    }

    return buffer;
}

} // namespace


RouteInfo getDefaultRoute()
{
    RouteInfo result;

    /*
     * Linux route query.
     *
     * This code is isolated here so
     * command_handler.cpp remains
     * completely platform-independent.
     */
    FILE* pipe =
        popen(
            "ip route show default 2>/dev/null",
            "r"
        );

    if (pipe == nullptr)
    {
        return result;
    }

    char buffer[512]{};

    std::string output;

    while (
        fgets(
            buffer,
            sizeof(buffer),
            pipe
        )
    )
    {
        output += buffer;
    }

    pclose(pipe);

    if (output.empty())
    {
        return result;
    }

    /*
     * Expected:
     *
     * default via 10.108.155.140
     * dev eth1 ...
     */

    const std::string viaToken =
        "default via ";

    const std::size_t via =
        output.find(
            viaToken
        );

    if (via != std::string::npos)
    {
        const std::size_t start =
            via + viaToken.size();

        const std::size_t end =
            output.find(
                ' ',
                start
            );

        result.gateway =
            output.substr(
                start,
                end == std::string::npos
                    ? std::string::npos
                    : end - start
            );
    }

    const std::string devToken =
        " dev ";

    const std::size_t dev =
        output.find(
            devToken
        );

    if (dev != std::string::npos)
    {
        const std::size_t start =
            dev + devToken.size();

        const std::size_t end =
            output.find(
                ' ',
                start
            );

        result.interfaceName =
            output.substr(
                start,
                end == std::string::npos
                    ? std::string::npos
                    : end - start
            );
    }

    /*
     * Find the IPv4 address belonging
     * to the selected interface.
     */
    if (
        !result.interfaceName.empty()
    )
    {
        ifaddrs* addresses = nullptr;

        if (
            getifaddrs(&addresses) == 0
        )
        {
            for (
                ifaddrs* current = addresses;
                current != nullptr;
                current = current->ifa_next
            )
            {
                if (
                    current->ifa_name == nullptr ||
                    current->ifa_addr == nullptr
                )
                {
                    continue;
                }

                if (
                    result.interfaceName
                    != current->ifa_name
                )
                {
                    continue;
                }

                if (
                    current->ifa_addr->sa_family
                    != AF_INET
                )
                {
                    continue;
                }

                result.localIP =
                    addressToString(
                        current->ifa_addr
                    );

                break;
            }

            freeifaddrs(addresses);
        }
    }

    result.valid =
        !result.interfaceName.empty() &&
        !result.localIP.empty();

    return result;
}

} // namespace slipnet::platform

#endif