#include "platform/dns.hpp"

#ifndef _WIN32

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <cstring>
#include <string>


namespace slipnet::platform
{

bool isIPAddress(
    const std::string& value
)
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


DNSPlatformResult resolveDNS(
    const std::string& input
)
{
    DNSPlatformResult result;


    /*
     * ========================================================
     * REVERSE DNS
     * ========================================================
     */
    if (
        isIPAddress(input)
    )
    {
        char host[NI_MAXHOST]{};

        sockaddr_storage address{};

        socklen_t addressLength = 0;


        /*
         * IPv4
         */
        sockaddr_in ipv4{};

        if (
            inet_pton(
                AF_INET,
                input.c_str(),
                &ipv4.sin_addr
            ) == 1
        )
        {
            ipv4.sin_family =
                AF_INET;

            std::memcpy(
                &address,
                &ipv4,
                sizeof(ipv4)
            );

            addressLength =
                sizeof(ipv4);
        }


        /*
         * IPv6
         */
        sockaddr_in6 ipv6{};

        if (
            inet_pton(
                AF_INET6,
                input.c_str(),
                &ipv6.sin6_addr
            ) == 1
        )
        {
            ipv6.sin6_family =
                AF_INET6;

            std::memcpy(
                &address,
                &ipv6,
                sizeof(ipv6)
            );

            addressLength =
                sizeof(ipv6);
        }


        if (
            addressLength == 0
        )
        {
            return result;
        }


        const int status =
            getnameinfo(
                reinterpret_cast<sockaddr*>(
                    &address
                ),
                addressLength,
                host,
                sizeof(host),
                nullptr,
                0,
                NI_NAMEREQD
            );


        /*
         * A valid IP without a PTR record
         * is still a valid DNS query.
         */
        if (
            status == 0 &&
            host[0] != '\0'
        )
        {
            result.reverseName =
                host;

            result.success =
                true;
        }
        else
        {
            result.success =
                true;
        }


        return result;
    }


    /*
     * ========================================================
     * FORWARD DNS
     * ========================================================
     */
    addrinfo hints{};

    hints.ai_family =
        AF_UNSPEC;

    hints.ai_socktype =
        SOCK_STREAM;


    addrinfo* results =
        nullptr;


    const int status =
        getaddrinfo(
            input.c_str(),
            nullptr,
            &hints,
            &results
        );


    if (
        status != 0 ||
        results == nullptr
    )
    {
        return result;
    }


    for (
        addrinfo* current =
            results;
        current != nullptr;
        current =
            current->ai_next
    )
    {
        char address[
            INET6_ADDRSTRLEN
        ]{};


        if (
            current->ai_family ==
            AF_INET
        )
        {
            const auto* ipv4 =
                reinterpret_cast<
                    const sockaddr_in*
                >(
                    current->ai_addr
                );


            inet_ntop(
                AF_INET,
                &ipv4->sin_addr,
                address,
                sizeof(address)
            );
        }
        else if (
            current->ai_family ==
            AF_INET6
        )
        {
            const auto* ipv6 =
                reinterpret_cast<
                    const sockaddr_in6*
                >(
                    current->ai_addr
                );


            inet_ntop(
                AF_INET6,
                &ipv6->sin6_addr,
                address,
                sizeof(address)
            );
        }


        if (
            address[0] != '\0'
        )
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


    freeaddrinfo(
        results
    );


    result.success =
        !result.addresses.empty();


    return result;
}

} // namespace slipnet::platform

#endif