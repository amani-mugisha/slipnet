#include "platform/dns.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <string>


namespace slipnet::platform
{

bool isIPAddress(
    const std::string& value
)
{
    IN_ADDR ipv4{};

    if (
        InetPtonA(
            AF_INET,
            value.c_str(),
            &ipv4
        ) == 1
    )
    {
        return true;
    }


    IN6_ADDR ipv6{};

    return
        InetPtonA(
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
     *
     * Input:
     *
     *     10.108.155.140
     *
     * We perform a PTR lookup.
     */
    if (
        isIPAddress(input)
    )
    {
        char host[NI_MAXHOST]{};

        SOCKADDR_STORAGE address{};

        int addressLength = 0;


        /*
         * IPv4
         */
        SOCKADDR_IN ipv4{};

        if (
            InetPtonA(
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
        SOCKADDR_IN6 ipv6{};

        if (
            InetPtonA(
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
                reinterpret_cast<SOCKADDR*>(
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
         * A missing PTR record is not an
         * application error.
         *
         * The address itself is valid.
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
            /*
             * Keep the result usable even when
             * reverse DNS is unavailable.
             */
            result.success =
                true;
        }


        return result;
    }


    /*
     * ========================================================
     * FORWARD DNS
     * ========================================================
     *
     * Input:
     *
     *     example.com
     *
     * Resolve hostname -> IPv4 / IPv6 addresses.
     */
    ADDRINFOA hints{};

    hints.ai_family =
        AF_UNSPEC;

    hints.ai_socktype =
        SOCK_STREAM;


    PADDRINFOA results =
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
        PADDRINFOA current =
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
                    const SOCKADDR_IN*
                >(
                    current->ai_addr
                );


            InetNtopA(
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
                    const SOCKADDR_IN6*
                >(
                    current->ai_addr
                );


            InetNtopA(
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