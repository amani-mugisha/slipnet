#include "network/dns_resolver.hpp"

#include <arpa/inet.h>
#include <netdb.h>

#include <cstring>

DNSResult DNSResolver::resolve(
    const std::string& input
) const
{
    DNSResult result;

    result.input = input;

    if (isIPAddress(input))
    {
        char host[NI_MAXHOST]{};

        sockaddr_storage address{};
        socklen_t length = 0;

        sockaddr_in ipv4{};

        if (
            inet_pton(
                AF_INET,
                input.c_str(),
                &ipv4.sin_addr
            ) == 1
        )
        {
            ipv4.sin_family = AF_INET;

            std::memcpy(
                &address,
                &ipv4,
                sizeof(ipv4)
            );

            length = sizeof(ipv4);
        }

        sockaddr_in6 ipv6{};

        if (
            inet_pton(
                AF_INET6,
                input.c_str(),
                &ipv6.sin6_addr
            ) == 1
        )
        {
            ipv6.sin6_family = AF_INET6;

            std::memcpy(
                &address,
                &ipv6,
                sizeof(ipv6)
            );

            length = sizeof(ipv6);
        }

        if (
            length > 0 &&
            getnameinfo(
                reinterpret_cast<sockaddr*>(&address),
                length,
                host,
                sizeof(host),
                nullptr,
                0,
                NI_NAMEREQD
            ) == 0
        )
        {
            result.reverseName = host;
            result.success = true;
        }

        return result;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* results = nullptr;

    int status =
        getaddrinfo(
            input.c_str(),
            nullptr,
            &hints,
            &results
        );

    if (status != 0)
    {
        return result;
    }

    for (
        addrinfo* current = results;
        current != nullptr;
        current = current->ai_next
    )
    {
        char address[INET6_ADDRSTRLEN]{};

        if (
            current->ai_family == AF_INET
        )
        {
            auto* ipv4 =
                reinterpret_cast<
                    sockaddr_in*
                >(current->ai_addr);

            inet_ntop(
                AF_INET,
                &ipv4->sin_addr,
                address,
                sizeof(address)
            );
        }
        else if (
            current->ai_family == AF_INET6
        )
        {
            auto* ipv6 =
                reinterpret_cast<
                    sockaddr_in6*
                >(current->ai_addr);

            inet_ntop(
                AF_INET6,
                &ipv6->sin6_addr,
                address,
                sizeof(address)
            );
        }

        if (address[0] != '\0')
        {
            result.addresses.emplace_back(
                address
            );
        }

        if (
            result.canonicalName.empty() &&
            current->ai_canonname != nullptr
        )
        {
            result.canonicalName =
                current->ai_canonname;
        }
    }

    freeaddrinfo(results);

    result.success =
        !result.addresses.empty();

    return result;
}


bool DNSResolver::isIPAddress(
    const std::string& value
) const
{
    in_addr ipv4{};

    if (
        inet_pton(
            AF_INET,
            value.c_str(),
            &ipv4
        ) == 1
    )
    {
        return true;
    }

    in6_addr ipv6{};

    return
        inet_pton(
            AF_INET6,
            value.c_str(),
            &ipv6
        ) == 1;
}