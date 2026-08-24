#include "platform/route.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <vector>

namespace slipnet::platform
{

namespace
{

bool initializeWinsock()
{
    static bool initialized = []()
    {
        WSADATA data{};

        return
            WSAStartup(
                MAKEWORD(2, 2),
                &data
            ) == 0;
    }();

    return initialized;
}

std::string ipv4ToString(
    const SOCKADDR* address
)
{
    if (
        address == nullptr ||
        address->sa_family != AF_INET
    )
    {
        return {};
    }

    char buffer[INET_ADDRSTRLEN]{};

    const auto* ipv4 =
        reinterpret_cast<const SOCKADDR_IN*>(
            address
        );

    if (
        inet_ntop(
            AF_INET,
            &ipv4->sin_addr,
            buffer,
            sizeof(buffer)
        ) == nullptr
    )
    {
        return {};
    }

    return buffer;
}

} // namespace


RouteInfo getDefaultRoute()
{
    RouteInfo result;

    if (!initializeWinsock())
    {
        return result;
    }

    /*
     * Get the route to an external IPv4
     * address. Windows chooses the interface
     * and gateway using its routing table.
     */
    IN_ADDR destination{};

    inet_pton(
        AF_INET,
        "1.1.1.1",
        &destination
    );

    MIB_IPFORWARDROW route{};

    DWORD status =
        GetBestRoute(
            destination.S_un.S_addr,
            0,
            &route
        );

    if (status != NO_ERROR)
    {
        return result;
    }

    /*
     * Gateway.
     */
    IN_ADDR gateway{};

    gateway.S_un.S_addr =
        route.dwForwardNextHop;

    char gatewayBuffer[
        INET_ADDRSTRLEN
    ]{};

    if (
        inet_ntop(
            AF_INET,
            &gateway,
            gatewayBuffer,
            sizeof(gatewayBuffer)
        ) != nullptr
    )
    {
        result.gateway =
            gatewayBuffer;
    }

    /*
     * Resolve interface information.
     */
    ULONG bufferSize = 0;

    GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_INCLUDE_PREFIX,
        nullptr,
        nullptr,
        &bufferSize
    );

    if (bufferSize == 0)
    {
        return result;
    }

    std::vector<unsigned char> buffer(
        bufferSize
    );

    auto* adapters =
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(
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

    if (status != NO_ERROR)
    {
        return result;
    }

    for (
        auto* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next
    )
    {
        if (
            adapter->IfIndex
            != route.dwForwardIfIndex
        )
        {
            continue;
        }

        if (
            adapter->FriendlyName != nullptr
        )
        {
            std::wstring name =
                adapter->FriendlyName;

            result.interfaceName.assign(
                name.begin(),
                name.end()
            );
        }

        for (
            auto* address =
                adapter->FirstUnicastAddress;
            address != nullptr;
            address = address->Next
        )
        {
            if (
                address->Address.lpSockaddr
                == nullptr
            )
            {
                continue;
            }

            if (
                address->Address.lpSockaddr->sa_family
                != AF_INET
            )
            {
                continue;
            }

            result.localIP =
                ipv4ToString(
                    address->Address.lpSockaddr
                );

            if (!result.localIP.empty())
            {
                break;
            }
        }

        break;
    }

    result.valid =
        !result.interfaceName.empty() &&
        !result.localIP.empty();

    return result;
}

} // namespace slipnet::platform

#endif