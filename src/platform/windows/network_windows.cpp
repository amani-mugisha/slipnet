#include "platform/network.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace slipnet::platform {

namespace {

std::string macToString(
    const BYTE* address,
    ULONG length
)
{
    if (
        address == nullptr ||
        length == 0
    ) {
        return {};
    }

    std::ostringstream output;

    for (
        ULONG i = 0;
        i < length;
        ++i
    ) {
        if (i > 0) {
            output << ':';
        }

        output
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(address[i]);
    }

    return output.str();
}


std::string ipv4ToString(
    const SOCKADDR* address
)
{
    if (
        address == nullptr ||
        address->sa_family != AF_INET
    ) {
        return {};
    }

    char buffer[INET_ADDRSTRLEN]{};

    const auto* ipv4 =
        reinterpret_cast<
            const SOCKADDR_IN*
        >(address);

    if (
        inet_ntop(
            AF_INET,
            &(ipv4->sin_addr),
            buffer,
            sizeof(buffer)
        ) == nullptr
    ) {
        return {};
    }

    return buffer;
}


std::string prefixLengthToNetmask(
    ULONG prefixLength
)
{
    if (prefixLength > 32) {
        return {};
    }

    if (prefixLength == 0) {
        return "0.0.0.0";
    }

    unsigned long mask =
        0xFFFFFFFFUL
        << (32 - prefixLength);

    std::ostringstream output;

    output
        << ((mask >> 24) & 0xFF)
        << '.'
        << ((mask >> 16) & 0xFF)
        << '.'
        << ((mask >> 8) & 0xFF)
        << '.'
        << (mask & 0xFF);

    return output.str();
}

} // namespace


std::vector<NetworkInterfaceInfo>
getNetworkInterfaces()
{
    std::vector<NetworkInterfaceInfo> interfaces;

    ULONG bufferSize = 0;

    DWORD result =
        GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            nullptr,
            &bufferSize
        );

    if (
        result !=
        ERROR_BUFFER_OVERFLOW
    ) {
        return interfaces;
    }

    std::vector<unsigned char> buffer(
        bufferSize
    );

    auto* adapters =
        reinterpret_cast<
            IP_ADAPTER_ADDRESSES*
        >(buffer.data());

    result =
        GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            adapters,
            &bufferSize
        );

    if (
        result != NO_ERROR
    ) {
        return interfaces;
    }


    for (
        auto* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next
    ) {

        NetworkInterfaceInfo info;


        /*
         * Friendly interface name.
         */
        if (
            adapter->FriendlyName != nullptr
        ) {
            std::wstring name(
                adapter->FriendlyName
            );

            info.name.assign(
                name.begin(),
                name.end()
            );
        }


        /*
         * Hardware/device description.
         */
        if (
            adapter->Description != nullptr
        ) {
            std::wstring description(
                adapter->Description
            );

            info.description.assign(
                description.begin(),
                description.end()
            );
        }


        /*
         * Interface state.
         */
        info.up =
            adapter->OperStatus ==
            IfOperStatusUp;


        /*
         * MAC address.
         */
        info.macAddress =
            macToString(
                adapter->PhysicalAddress,
                adapter->PhysicalAddressLength
            );


        /*
         * IPv4 address and subnet mask.
         */
        for (
            auto* address =
                adapter->FirstUnicastAddress;
            address != nullptr;
            address = address->Next
        ) {

            if (
                address->Address.lpSockaddr ==
                nullptr
            ) {
                continue;
            }


            if (
                address->Address.lpSockaddr->sa_family
                != AF_INET
            ) {
                continue;
            }


            info.ipv4Address =
                ipv4ToString(
                    address->Address.lpSockaddr
                );


            info.netmask =
                prefixLengthToNetmask(
                    address->OnLinkPrefixLength
                );


            break;
        }


        /*
         * Only expose interfaces that
         * actually have an IPv4 address.
         */
        if (
            !info.ipv4Address.empty()
        ) {
            interfaces.push_back(
                std::move(info)
            );
        }
    }


    return interfaces;
}

} // namespace slipnet::platform

#endif