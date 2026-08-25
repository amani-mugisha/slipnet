#include "host/host_discovery.hpp"

#include "platform/ping.hpp"

#include <cstdint>
#include <future>
#include <sstream>
#include <string>
#include <vector>


namespace
{

uint32_t prefixToMask(
    int prefix
)
{
    if (prefix <= 0)
    {
        return 0;
    }

    if (prefix >= 32)
    {
        return 0xFFFFFFFFu;
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
            std::size_t position = 0;

            octet =
                std::stoi(
                    part,
                    &position
                );

            if (position != part.size())
            {
                return false;
            }
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
            static_cast<uint32_t>(octet);

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


Host
HostDiscovery::check(
    const std::string& ip
) const
{
    Host result;

    result.ip =
        ip;

    result.reachable =
        false;

    result.latencyMs =
        0.0;


    /*
     * --------------------------------------------------------
     * Host validation
     * --------------------------------------------------------
     *
     * host|:find is a single-host operation.
     *
     * CIDR notation belongs to subnet/network discovery.
     *
     * Example:
     *
     *   Valid:
     *       host|:find 10.108.155.140
     *
     *   Invalid:
     *       host|:find 10.108.155.0/24
     *
     * The CLI layer can provide the user-facing explanation.
     */

    if (
        ip.find('/') !=
        std::string::npos
    )
    {
        return result;
    }


    /*
     * --------------------------------------------------------
     * Platform-specific reachability probe
     * --------------------------------------------------------
     *
     * Linux:
     *     src/platform/linux/ping_linux.cpp
     *
     * Windows:
     *     src/platform/windows/ping_windows.cpp
     */

    const auto pingResult =
        slipnet::platform::pingHost(
            ip
        );


    result.reachable =
        pingResult.reachable;

    result.latencyMs =
        pingResult.latencyMs;


    return result;
}


std::vector<std::string>
HostDiscovery::generateHosts(
    const std::string& cidr
) const
{
    std::vector<std::string> hosts;


    /*
     * --------------------------------------------------------
     * Parse CIDR
     * --------------------------------------------------------
     */

    const std::size_t slash =
        cidr.find('/');

    if (
        slash ==
        std::string::npos
    )
    {
        return hosts;
    }


    const std::string ip =
        cidr.substr(
            0,
            slash
        );

    const std::string prefixText =
        cidr.substr(
            slash + 1
        );


    uint32_t address = 0;

    if (
        !parseIPv4(
            ip,
            address
        )
    )
    {
        return hosts;
    }


    int prefix = 0;

    try
    {
        std::size_t position = 0;

        prefix =
            std::stoi(
                prefixText,
                &position
            );

        if (
            position !=
            prefixText.size()
        )
        {
            return hosts;
        }
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


    /*
     * --------------------------------------------------------
     * Calculate network
     * --------------------------------------------------------
     */

    const uint32_t mask =
        prefixToMask(prefix);

    const uint32_t network =
        address & mask;


    /*
     * --------------------------------------------------------
     * Generate addresses
     * --------------------------------------------------------
     *
     * For IPv4 /24:
     *
     *     network     = x.x.x.0
     *     broadcast   = x.x.x.255
     *
     * We exclude network and broadcast addresses.
     */

    uint32_t firstHost =
        network;

    uint32_t lastHost =
        network;


    if (prefix <= 30)
    {
        const uint32_t hostCount =
            1u << (32 - prefix);

        firstHost =
            network + 1;

        lastHost =
            network +
            hostCount -
            2;
    }
    else if (prefix == 31)
    {
        firstHost =
            network;

        lastHost =
            network + 1;
    }
    else
    {
        /*
         * /32 represents exactly one address.
         */
        firstHost =
            network;

        lastHost =
            network;
    }


    /*
     * --------------------------------------------------------
     * Build host list
     * --------------------------------------------------------
     */

    for (
        uint32_t current = firstHost;
        current <= lastHost;
        ++current
    )
    {
        hosts.emplace_back(
            ipv4ToString(
                current
            )
        );

        /*
         * Prevent unsigned wraparound.
         */
        if (current == lastHost)
        {
            break;
        }
    }


    return hosts;
}


std::vector<Host>
HostDiscovery::scanSubnet(
    const std::string& cidr
) const
{
    std::vector<Host> results;


    const auto hosts =
        generateHosts(
            cidr
        );


    if (hosts.empty())
    {
        return results;
    }


    /*
     * --------------------------------------------------------
     * Concurrent host discovery
     * --------------------------------------------------------
     *
     * Limit concurrency to avoid creating an excessive number
     * of simultaneous tasks.
     */

    constexpr std::size_t MAX_CONCURRENCY =
        32;


    results.reserve(
        hosts.size()
    );


    for (
        std::size_t index = 0;
        index < hosts.size();
        index += MAX_CONCURRENCY
    )
    {
        const std::size_t end =
            std::min(
                index + MAX_CONCURRENCY,
                hosts.size()
            );


        std::vector<
            std::future<Host>
        > futures;


        futures.reserve(
            end - index
        );


        for (
            std::size_t i = index;
            i < end;
            ++i
        )
        {
            futures.emplace_back(
                std::async(
                    std::launch::async,
                    &HostDiscovery::check,
                    this,
                    hosts[i]
                )
            );
        }


        for (
            auto& future :
            futures
        )
        {
            results.emplace_back(
                future.get()
            );
        }
    }


    return results;
}