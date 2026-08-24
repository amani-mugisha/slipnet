#include "platform/network.hpp"

#ifndef _WIN32

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>

#include <cstring>
#include <iomanip>
#include <sstream>

namespace slipnet::platform {

namespace {

std::string addressToString(
    const sockaddr* address
)
{
    if (address == nullptr) {
        return {};
    }

    char buffer[INET6_ADDRSTRLEN]{};

    if (address->sa_family == AF_INET) {

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
            ) != nullptr
        ) {
            return buffer;
        }
    }

    return {};
}


std::string macAddressToString(
    const unsigned char* mac
)
{
    if (mac == nullptr) {
        return {};
    }

    std::ostringstream output;

    output
        << std::hex
        << std::setfill('0')
        << std::setw(2)
        << static_cast<int>(mac[0])
        << ":"
        << std::setw(2)
        << static_cast<int>(mac[1])
        << ":"
        << std::setw(2)
        << static_cast<int>(mac[2])
        << ":"
        << std::setw(2)
        << static_cast<int>(mac[3])
        << ":"
        << std::setw(2)
        << static_cast<int>(mac[4])
        << ":"
        << std::setw(2)
        << static_cast<int>(mac[5]);

    return output.str();
}

} // namespace


std::vector<NetworkInterfaceInfo>
getNetworkInterfaces()
{
    std::vector<NetworkInterfaceInfo> interfaces;

    ifaddrs* addresses = nullptr;

    if (
        getifaddrs(&addresses) != 0
    ) {
        return interfaces;
    }


    for (
        ifaddrs* current = addresses;
        current != nullptr;
        current = current->ifa_next
    ) {

        if (
            current->ifa_name == nullptr
        ) {
            continue;
        }

        if (
            current->ifa_addr == nullptr
        ) {
            continue;
        }


        /*
         * We only want IPv4 interfaces
         * for the current discovery engine.
         */
        if (
            current->ifa_addr->sa_family !=
            AF_INET
        ) {
            continue;
        }

        if (
            std::string(current->ifa_name) == "lo"
        )
        {
            continue;
        }


        NetworkInterfaceInfo info;

        info.name =
            current->ifa_name;

        info.description =
            info.name;

        info.ipv4Address =
            addressToString(
                current->ifa_addr
            );

        info.netmask =
            addressToString(
                current->ifa_netmask
            );

        info.up =
            (current->ifa_flags &
             IFF_UP) != 0;


        /*
         * Ignore interfaces that don't
         * have a usable IPv4 address.
         */
        if (
            info.ipv4Address.empty()
        ) {
            continue;
        }


        /*
         * Find the MAC address by
         * matching the interface name.
         *
         * This is intentionally kept
         * lightweight for now.
         */
        if (
            current->ifa_flags &
            IFF_LOOPBACK
        ) {
            info.macAddress =
                "00:00:00:00:00:00";
        }


        interfaces.push_back(
            std::move(info)
        );
    }


    freeifaddrs(addresses);

    return interfaces;
}

} // namespace slipnet::platform

#endif