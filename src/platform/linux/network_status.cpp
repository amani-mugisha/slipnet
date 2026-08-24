#include "platform/network_status.hpp"

#ifndef _WIN32

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

namespace slipnet::platform
{

namespace
{

std::uint64_t readCounter(
    const std::string& interfaceName,
    const std::string& counter
)
{
    const std::string path =
        "/sys/class/net/" +
        interfaceName +
        "/statistics/" +
        counter;

    std::ifstream file(path);

    if (!file)
    {
        return 0;
    }

    std::uint64_t value = 0;

    file >> value;

    return value;
}


std::string getIPv4Address(
    const std::string& interfaceName
)
{
    ifaddrs* addresses = nullptr;

    if (getifaddrs(&addresses) != 0)
    {
        return {};
    }

    std::string result;

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
            interfaceName != current->ifa_name
        )
        {
            continue;
        }

        if (
            current->ifa_addr->sa_family != AF_INET
        )
        {
            continue;
        }

        const auto* address =
            reinterpret_cast<const sockaddr_in*>(
                current->ifa_addr
            );

        char buffer[INET_ADDRSTRLEN]{};

        if (
            inet_ntop(
                AF_INET,
                &address->sin_addr,
                buffer,
                sizeof(buffer)
            ) != nullptr
        )
        {
            result = buffer;
        }

        break;
    }

    freeifaddrs(addresses);

    return result;
}

} // namespace


NetworkStatus getNetworkStatus(
    const std::string& interfaceName
)
{
    NetworkStatus status;

    status.interfaceName =
        interfaceName;

    if (interfaceName.empty())
    {
        return status;
    }

    status.ipv4Address =
        getIPv4Address(interfaceName);

    const std::string operstatePath =
        "/sys/class/net/" +
        interfaceName +
        "/operstate";

    std::ifstream operstate(
        operstatePath
    );

    std::string state;

    if (operstate)
    {
        operstate >> state;
    }

    status.up =
        state == "up";

    status.rxBytes =
        readCounter(
            interfaceName,
            "rx_bytes"
        );

    status.txBytes =
        readCounter(
            interfaceName,
            "tx_bytes"
        );

    status.rxPackets =
        readCounter(
            interfaceName,
            "rx_packets"
        );

    status.txPackets =
        readCounter(
            interfaceName,
            "tx_packets"
        );

    status.rxErrors =
        readCounter(
            interfaceName,
            "rx_errors"
        );

    status.txErrors =
        readCounter(
            interfaceName,
            "tx_errors"
        );

    status.rxDropped =
        readCounter(
            interfaceName,
            "rx_dropped"
        );

    status.txDropped =
        readCounter(
            interfaceName,
            "tx_dropped"
        );

    return status;
}


std::string detectActiveInterface()
{
    ifaddrs* addresses = nullptr;

    if (getifaddrs(&addresses) != 0)
    {
        return {};
    }

    std::string fallback;

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
            current->ifa_addr->sa_family != AF_INET
        )
        {
            continue;
        }

        const std::string name =
            current->ifa_name;

        if (name == "lo")
        {
            continue;
        }

        if (
            (current->ifa_flags & IFF_UP) == 0
        )
        {
            continue;
        }

        if (
            (current->ifa_flags & IFF_RUNNING) != 0
        )
        {
            freeifaddrs(addresses);
            return name;
        }

        if (fallback.empty())
        {
            fallback = name;
        }
    }

    freeifaddrs(addresses);

    return fallback;
}


bool networkStatusAvailable()
{
    return true;
}

} // namespace slipnet::platform

#endif