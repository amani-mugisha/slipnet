#include "platform/network_status.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
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
        reinterpret_cast<const SOCKADDR_IN*>(
            address
        );

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

    ULONG bufferSize = 0;

    DWORD result =
        GetIfTable2(nullptr, &bufferSize);

    if (
        result != ERROR_INSUFFICIENT_BUFFER
    )
    {
        return status;
    }

    /*
     * GetIfTable2 allocates the table itself.
     * bufferSize is only used to detect API
     * availability, so request the table again.
     */
    MIB_IF_TABLE2* table = nullptr;

    result =
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

        if (
            interfaceName != name &&
            interfaceName != description
        )
        {
            continue;
        }

        status.interfaceName = name;

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

        status.ipv4Address.clear();

        FreeMibTable(table);

        return status;
    }

    FreeMibTable(table);

    return status;
}


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
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(
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

    if (result != NO_ERROR)
    {
        return {};
    }

    for (
        auto* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next
    )
    {
        if (
            adapter->OperStatus !=
            IfOperStatusUp
        )
        {
            continue;
        }

        if (
            adapter->IfType ==
            IF_TYPE_SOFTWARE_LOOPBACK
        )
        {
            continue;
        }

        if (
            adapter->FirstUnicastAddress == nullptr
        )
        {
            continue;
        }

        if (
            adapter->FriendlyName == nullptr
        )
        {
            continue;
        }

        return wideToString(
            adapter->FriendlyName
        );
    }

    return {};
}


bool networkStatusAvailable()
{
    return true;
}

} // namespace slipnet::platform

#endif