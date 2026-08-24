#include "host/host_discovery.hpp"

#include "platform/ping.hpp"

#include <future>
#include <iostream>
#include <thread>

#include <cstdint>
#include <sstream>


namespace
{

uint32_t prefixToMask(
    int prefix
)
{
    if (prefix == 0)
    {
        return 0;
    }

    return
        0xFFFFFFFFu <<
        (32 - prefix);
}


bool parseIPv4(
    const std::string& ip,
    uint32_t& value
)
{
    std::stringstream stream(ip);

    std::string part;

    uint32_t result = 0;

    int count = 0;

    while (
        std::getline(
            stream,
            part,
            '.'
        )
    )
    {
        if (part.empty())
        {
            return false;
        }

        int octet = 0;

        try
        {
            octet =
                std::stoi(part);
        }
        catch (...)
        {
            return false;
        }

        if (
            octet < 0 ||
            octet > 255
        )
        {
            return false;
        }

        result =
            (result << 8) |
            static_cast<uint32_t>(
                octet
            );

        ++count;
    }

    if (count != 4)
    {
        return false;
    }

    value = result;

    return true;
}


std::string ipv4ToString(
    uint32_t value
)
{
    return
        std::to_string(
            (value >> 24) & 0xFF
        )
        + "."
        +
        std::to_string(
            (value >> 16) & 0xFF
        )
        + "."
        +
        std::to_string(
            (value >> 8) & 0xFF
        )
        + "."
        +
        std::to_string(
            value & 0xFF
        );
}

} // namespace


Host HostDiscovery::check(
    const std::string& ip
) const
{
    Host result;

    result.ip = ip;
    result.reachable = false;
    result.latencyMs = 0.0;

    // host|:find accepts a single IPv4 address only.
    // CIDR notation such as 192.168.1.0/24 is invalid here.
    if (ip.find('/') != std::string::npos)
    {
        return result;
    }

    // Continue with the normal host check...

    const auto pingResult =
        slipnet::platform::pingHost(
            ip
        );

    result.reachable =
        pingResult.reachable;

    result.latencyMs =
        pingResult.latencyMs;

    return result;

    if (ip.find('/') != std::string::npos)
    {
        std::cout
            << "\n[!] Invalid host address.\n"
            << "\n"
            << "    host|:find expects a single IPv4 address.\n"
            << "\n"
            << "    Example:\n"
            << "    host|:find 10.108.155.140\n"
            << "\n";

        return result;
    }
}


std::vector<std::string>
HostDiscovery::generateHosts(
    const std::string& cidr
) const
{
    std::vector<std::string> hosts;

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

    int prefix = 0;

    try
    {
        prefix =
            std::stoi(prefixText);
    }
    catch (...)
    {
        return hosts;
    }

    if (
        prefix < 0 ||
        prefix > 32
    )
    {
        return hosts;
    }

    uint32_t ipValue = 0;

    if (
        !parseIPv4(
            ip,
            ipValue
        )
    )
    {
        return hosts;
    }

    uint32_t mask =
        prefixToMask(prefix);

    uint32_t network =
        ipValue & mask;

    uint32_t broadcast =
        network | (~mask);

    uint32_t firstHost =
        network;

    uint32_t lastHost =
        broadcast;

    if (prefix <= 30)
    {
        firstHost =
            network + 1;

        lastHost =
            broadcast - 1;
    }

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

    if (
        hostCount >
        MAX_HOSTS
    )
    {
        std::cout
            << "Subnet is too large.\n"
            << "Maximum supported scan size: "
            << MAX_HOSTS
            << " hosts.\n";

        return hosts;
    }

    for (
        uint32_t current =
            firstHost;
        current <= lastHost;
        ++current
    )
    {
        hosts.push_back(
            ipv4ToString(
                current
            )
        );
    }

    return hosts;
}


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