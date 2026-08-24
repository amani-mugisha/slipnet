#include "platform/topology.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <iphlpapi.h>

#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace slipnet::platform {

namespace {

std::string wideToString(
    const wchar_t* value
)
{
    if (value == nullptr)
    {
        return {};
    }

    std::wstring wide(value);

    return std::string(
        wide.begin(),
        wide.end()
    );
}

} // namespace

LocalTopologyInfo getLocalTopologyInfo()
{
    LocalTopologyInfo info;

    ULONG bufferSize = 0;

    DWORD result =
        GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_GATEWAYS,
            nullptr,
            nullptr,
            &bufferSize
        );

    if (result != ERROR_BUFFER_OVERFLOW)
    {
        return info;
    }

    std::vector<unsigned char> buffer(
        bufferSize
    );

    auto* adapters =
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(
            buffer.data()
        );

    result =
        GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_GATEWAYS,
            nullptr,
            adapters,
            &bufferSize
        );

    if (result != NO_ERROR)
    {
        return info;
    }

    for (
        auto* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next
    )
    {
        if (
            adapter->OperStatus
            != IfOperStatusUp
        )
        {
            continue;
        }

        /*
         * Ignore loopback adapters.
         */
        if (
            adapter->IfType
            == IF_TYPE_SOFTWARE_LOOPBACK
        )
        {
            continue;
        }

        if (adapter->FriendlyName != nullptr)
        {
            info.interfaceName =
                wideToString(
                    adapter->FriendlyName
                );
        }

        /*
         * Find IPv4 address.
         */
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

            char ipBuffer[INET_ADDRSTRLEN]{};

            auto* ipv4 =
                reinterpret_cast<SOCKADDR_IN*>(
                    address->Address.lpSockaddr
                );

            if (
                InetNtopA(
                    AF_INET,
                    &ipv4->sin_addr,
                    ipBuffer,
                    sizeof(ipBuffer)
                ) != nullptr
            )
            {
                info.localAddress =
                    ipBuffer;
            }

            break;
        }

        /*
         * Find default gateway.
         */
        if (
            adapter->FirstGatewayAddress
            != nullptr
        )
        {
            auto* gateway =
                adapter->FirstGatewayAddress;

            if (
                gateway->Address.lpSockaddr
                != nullptr &&
                gateway->Address.lpSockaddr->sa_family
                == AF_INET
            )
            {
                char gatewayBuffer[
                    INET_ADDRSTRLEN
                ]{};

                auto* ipv4 =
                    reinterpret_cast<SOCKADDR_IN*>(
                        gateway->Address.lpSockaddr
                    );

                if (
                    InetNtopA(
                        AF_INET,
                        &ipv4->sin_addr,
                        gatewayBuffer,
                        sizeof(gatewayBuffer)
                    ) != nullptr
                )
                {
                    info.gatewayAddress =
                        gatewayBuffer;
                }
            }
        }

        if (
            !info.localAddress.empty()
        )
        {
            break;
        }
    }

    return info;
}

} // namespace slipnet::platform

#endif