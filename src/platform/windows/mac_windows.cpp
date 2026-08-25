#include "platform/mac.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

/*
 * Winsock must be included before Windows headers.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace
{

std::string
formatMac(
    const BYTE* address,
    ULONG length
)
{
    if (
        address == nullptr ||
        length == 0
    )
    {
        return {};
    }

    std::ostringstream result;

    result
        << std::uppercase
        << std::hex
        << std::setfill('0');

    for (
        ULONG i = 0;
        i < length;
        ++i
    )
    {
        if (i > 0)
        {
            result << ':';
        }

        result
            << std::setw(2)
            << static_cast<unsigned int>(
                address[i]
            );
    }

    return result.str();
}


std::string
findInterfaceName(
    const std::string& ip
)
{
    IN_ADDR target{};

    if (
        inet_pton(
            AF_INET,
            ip.c_str(),
            &target
        ) != 1
    )
    {
        return "Unknown";
    }

    DWORD interfaceIndex = 0;

    if (
        GetBestInterface(
            target.S_un.S_addr,
            &interfaceIndex
        ) != NO_ERROR
    )
    {
        return "Unknown";
    }

    ULONG bufferSize = 0;

    DWORD status =
        GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            nullptr,
            &bufferSize
        );

    if (
        status !=
        ERROR_BUFFER_OVERFLOW
    )
    {
        return "Unknown";
    }

    std::vector<BYTE> buffer(
        bufferSize
    );

    auto* adapters =
        reinterpret_cast<
            PIP_ADAPTER_ADDRESSES
        >(
            buffer.data()
        );

    status =
        GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            adapters,
            &bufferSize
        );

    if (
        status != NO_ERROR
    )
    {
        return "Unknown";
    }

    for (
        auto* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next
    )
    {
        if (
            adapter->IfIndex ==
            interfaceIndex
        )
        {
            if (
                adapter->FriendlyName !=
                nullptr
            )
            {
                std::wstring name(
                    adapter->FriendlyName
                );

                return std::string(
                    name.begin(),
                    name.end()
                );
            }

            return "Unknown";
        }
    }

    return "Unknown";
}

} // namespace


namespace slipnet::platform
{

MacPlatformResolution
resolveMacAddress(
    const std::string& ip
)
{
    MacPlatformResolution result;

    IN_ADDR destination{};

    if (
        inet_pton(
            AF_INET,
            ip.c_str(),
            &destination
        ) != 1
    )
    {
        return result;
    }

    ULONG macAddress[2]{};

    ULONG physicalAddressLength = 6;

    const DWORD status =
        SendARP(
            destination.S_un.S_addr,
            0,
            macAddress,
            &physicalAddressLength
        );

    if (
        status != NO_ERROR ||
        physicalAddressLength < 6
    )
    {
        return result;
    }

    const auto* bytes =
        reinterpret_cast<const BYTE*>(
            macAddress
        );

    result.mac =
        formatMac(
            bytes,
            physicalAddressLength
        );

    if (
        result.mac.empty()
    )
    {
        return result;
    }

    result.found = true;

    result.interfaceName =
        findInterfaceName(ip);

    result.vendor =
        "Unknown";

    return result;
}

} // namespace slipnet::platform

#endif // _WIN32