#include "host/host_discovery.hpp"

#include <arpa/inet.h>

#include <chrono>

#include <cstring>

#include <future>

#include <iostream>

#include <netinet/ip_icmp.h>

#include <sys/socket.h>

#include <thread>

#include <unistd.h>


Host HostDiscovery::check(
    const std::string& ip
) const
{
    Host result;

    result.ip = ip;
    result.reachable = false;
    result.latencyMs = 0.0;

    int socketFD =
        socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_ICMP
        );

    if (socketFD < 0)
    {
        return result;
    }

    sockaddr_in destination{};

    destination.sin_family = AF_INET;

    if (
        inet_pton(
            AF_INET,
            ip.c_str(),
            &destination.sin_addr
        ) != 1
    )
    {
        close(socketFD);

        return result;
    }

    timeval timeout{};

    timeout.tv_sec = 1;

    timeout.tv_usec = 0;

    setsockopt(
        socketFD,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout)
    );


    /*
        ICMP Echo Request
    */

    struct icmphdr packet{};

    packet.type = ICMP_ECHO;

    packet.code = 0;

    packet.un.echo.id =
        static_cast<uint16_t>(
            getpid()
        );

    packet.un.echo.sequence = 1;


    auto start =
        std::chrono::steady_clock::now();


    sendto(
        socketFD,
        &packet,
        sizeof(packet),
        0,
        reinterpret_cast<sockaddr*>(
            &destination
        ),
        sizeof(destination)
    );


    char buffer[2048];

    sockaddr_in response{};

    socklen_t responseLength =
        sizeof(response);


    int received =
        recvfrom(
            socketFD,
            buffer,
            sizeof(buffer),
            0,
            reinterpret_cast<sockaddr*>(
                &response
            ),
            &responseLength
        );


    auto end =
        std::chrono::steady_clock::now();


    close(socketFD);


    if (received > 0)
    {
        result.reachable = true;

        result.latencyMs =
            std::chrono::duration<double, std::milli>(
                end - start
            ).count();
    }


    return result;
}


/*
    Convert CIDR prefix into a network mask.
*/
static uint32_t prefixToMask(
    int prefix
)
{
    if (prefix == 0)
    {
        return 0;
    }

    return
        0xFFFFFFFFu
        << (32 - prefix);
}


/*
    Generate usable IPv4 addresses
    from a CIDR subnet.
*/
std::vector<std::string>
HostDiscovery::generateHosts(
    const std::string& cidr
) const
{
    std::vector<std::string> hosts;


    /*
        Separate:

        192.168.1.0/24

        into:

        192.168.1.0
        24
    */

    std::size_t slash =
        cidr.find('/');

    if (slash == std::string::npos)
    {
        return hosts;
    }


    std::string ip =
        cidr.substr(
            0,
            slash
        );

    std::string prefixText =
        cidr.substr(
            slash + 1
        );


    int prefix =
        std::stoi(prefixText);


    if (prefix < 0 || prefix > 32)
    {
        return hosts;
    }


    struct in_addr address{};


    if (
        inet_pton(
            AF_INET,
            ip.c_str(),
            &address
        ) != 1
    )
    {
        return hosts;
    }


    uint32_t ipValue =
        ntohl(address.s_addr);


    uint32_t mask =
        prefixToMask(prefix);


    uint32_t network =
        ipValue & mask;


    uint32_t broadcast =
        network | (~mask);


    /*
        /31 and /32 don't have
        the normal network/broadcast
        host layout.
    */

    uint32_t firstHost = network;

    uint32_t lastHost = broadcast;


    if (prefix <= 30)
    {
        firstHost = network + 1;

        lastHost = broadcast - 1;
    }


    /*
        Safety limit.

        We don't want an accidental
        huge scan such as:

        10.0.0.0/8
    */

    constexpr uint64_t MAX_HOSTS =
        4096;


    uint64_t hostCount =
        static_cast<uint64_t>(
            lastHost
        ) -
        static_cast<uint64_t>(
            firstHost
        ) +
        1;


    if (hostCount > MAX_HOSTS)
    {
        std::cout
            << "Subnet is too large.\n"
            << "Maximum supported scan size: "
            << MAX_HOSTS
            << " hosts.\n";

        return hosts;
    }


    for (
        uint32_t current = firstHost;
        current <= lastHost;
        ++current
    )
    {
        struct in_addr currentAddress{};

        currentAddress.s_addr =
            htonl(current);


        char buffer[
            INET_ADDRSTRLEN
        ];


        inet_ntop(
            AF_INET,
            &currentAddress,
            buffer,
            INET_ADDRSTRLEN
        );


        hosts.emplace_back(
            buffer
        );
    }


    return hosts;
}


/*
    Concurrent subnet discovery.
*/
std::vector<Host>
HostDiscovery::scanSubnet(
    const std::string& cidr
) const
{
    std::vector<Host> results;


    std::vector<std::string> hosts =
        generateHosts(cidr);


    if (hosts.empty())
    {
        return results;
    }


    /*
        Limit the number of
        simultaneous checks.
    */

    unsigned int workerCount =
        std::thread::hardware_concurrency();


    if (workerCount == 0)
    {
        workerCount = 4;
    }


    if (workerCount > 32)
    {
        workerCount = 32;
    }


    std::vector<
        std::future<Host>
    > futures;


    for (
        const auto& ip :
        hosts
    )
    {
        futures.push_back(
            std::async(
                std::launch::async,
                &HostDiscovery::check,
                this,
                ip
            )
        );


        /*
            Keep the number of
            simultaneous tasks
            under control.
        */

        if (
            futures.size()
            >= workerCount
        )
        {
            for (
                auto& future :
                futures
            )
            {
                Host host =
                    future.get();

                if (host.reachable)
                {
                    results.push_back(
                        host
                    );
                }
            }


            futures.clear();
        }
    }


    /*
        Collect remaining tasks.
    */

    for (
        auto& future :
        futures
    )
    {
        Host host =
            future.get();

        if (host.reachable)
        {
            results.push_back(
                host
            );
        }
    }


    return results;
}