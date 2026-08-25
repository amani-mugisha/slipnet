#include "platform/network_status.hpp"

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

#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace slipnet::platform
{

namespace
{

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
    )
    {
        return {};
    }

    return buffer;
}

} // namespace


NetworkStatus getNetworkStatus(
    const std::string& interfaceName
)
{
    NetworkStatus status;

    status.interfaceName =
        interfaceName;

    /*
     * GetIfTable2 allocates the table itself.
     */
    MIB_IF_TABLE2* table = nullptr;

    DWORD result =
        GetIfTable2(&table);

    if (
        result != NO_ERROR ||
        table == nullptr
    )
    {
        return status;
    }

    for (
        ULONG i = 0;
        i < table->NumEntries;
        ++i
    )
    {
        const MIB_IF_ROW2& row =
            table->Table[i];

        const std::string name =
            wideToString(
                row.Alias
            );

        const std::string description =
            wideToString(
                row.Description
            );

        /*
         * Match either the Windows interface
         * alias or its description.
         */
        if (
            interfaceName != name &&
            interfaceName != description
        )
        {
            continue;
        }

        status.interfaceName =
            name;

        status.up =
            row.OperStatus ==
            IfOperStatusUp;

        status.rxBytes =
            row.InOctets;

        status.txBytes =
            row.OutOctets;

        status.rxPackets =
            row.InUcastPkts +
            row.InNUcastPkts;

        status.txPackets =
            row.OutUcastPkts +
            row.OutNUcastPkts;

        status.rxErrors =
            row.InErrors;

        status.txErrors =
            row.OutErrors;

        status.rxDropped =
            row.InDiscards;

        status.txDropped =
            row.OutDiscards;

        /*
         * Find IPv4 address for this interface.
         */
        ULONG addressBufferSize = 0;

        ULONG addressResult =
            GetAdaptersAddresses(
                AF_INET,
                GAA_FLAG_INCLUDE_PREFIX,
                nullptr,
                nullptr,
                &addressBufferSize
            );

        if (
            addressResult ==
            ERROR_BUFFER_OVERFLOW
        )
        {
            std::vector<unsigned char>
                addressBuffer(
                    addressBufferSize
                );

            auto* adapters =
                reinterpret_cast<
                    IP_ADAPTER_ADDRESSES*
                >(
                    addressBuffer.data()
                );

            addressResult =
                GetAdaptersAddresses(
                    AF_INET,
                    GAA_FLAG_INCLUDE_PREFIX,
                    nullptr,
                    adapters,
                    &addressBufferSize
                );

            if (
                addressResult ==
                NO_ERROR
            )
            {
                for (
                    auto* adapter = adapters;
                    adapter != nullptr;
                    adapter = adapter->Next
                )
                {
                    if (
                        adapter->IfIndex !=
                        row.InterfaceIndex
                    )
                    {
                        continue;
                    }

                    for (
                        auto* address =
                            adapter->FirstUnicastAddress;
                        address != nullptr;
                        address =
                            address->Next
                    )
                    {
                        const std::string ipv4 =
                            ipv4ToString(
                                address->Address.lpSockaddr
                            );

                        if (!ipv4.empty())
                        {
                            status.ipv4Address =
                                ipv4;

                            break;
                        }
                    }

                    if (
                        !status.ipv4Address.empty()
                    )
                    {
                        break;
                    }
                }
            }
        }

        break;
    }

    /*
     * GetIfTable2 allocates the table.
     * Release it after use.
     */
    FreeMibTable(table);

    return status;
}


/*
 * ------------------------------------------------------------
 * Detect active network interface
 * ------------------------------------------------------------
 *
 * Returns the Windows friendly name of the first active,
 * non-loopback interface that has an IPv4 address.
 */
std::string detectActiveInterface()
{
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
        result != ERROR_BUFFER_OVERFLOW
    )
    {
        return {};
    }

    std::vector<unsigned char> buffer(
        bufferSize
    );

    auto* adapters =
        reinterpret_cast<
            IP_ADAPTER_ADDRESSES*
        >(
            buffer.data()
        );

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
    )
    {
        return {};
    }

    for (
        auto* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next
    )
    {
        /*
         * Interface must be operational.
         */
        if (
            adapter->OperStatus !=
            IfOperStatusUp
        )
        {
            continue;
        }

        /*
         * Ignore loopback interfaces.
         */
        if (
            adapter->IfType ==
            IF_TYPE_SOFTWARE_LOOPBACK
        )
        {
            continue;
        }

        /*
         * Make sure the interface has an IPv4
         * address before considering it active.
         */
        bool hasIPv4 = false;

        for (
            auto* address =
                adapter->FirstUnicastAddress;
            address != nullptr;
            address = address->Next
        )
        {
            if (
                address->Address.lpSockaddr ==
                nullptr
            )
            {
                continue;
            }

            if (
                address->Address.lpSockaddr->sa_family ==
                AF_INET
            )
            {
                hasIPv4 = true;
                break;
            }
        }

        if (!hasIPv4)
        {
            continue;
        }

        if (
            adapter->FriendlyName !=
            nullptr
        )
        {
            return wideToString(
                adapter->FriendlyName
            );
        }

        /*
         * Fallback to adapter description.
         */
        if (
            adapter->Description !=
            nullptr
        )
        {
            return wideToString(
                adapter->Description
            );
        }
    }

    return {};
}


/*
 * ------------------------------------------------------------
 * Network status availability
 * ------------------------------------------------------------
 *
 * Windows provides the required network interface
 * APIs through IP Helper API.
 */
bool networkStatusAvailable()
{
    MIB_IF_TABLE2* table = nullptr;

    const DWORD result =
        GetIfTable2(&table);

    if (
        result != NO_ERROR ||
        table == nullptr
    )
    {
        return false;
    }

    FreeMibTable(table);

    return true;
}

} // namespace slipnet::platform

#endif // _WIN32