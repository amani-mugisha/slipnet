#include "platform/packet_capture.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <pcap.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace slipnet::platform
{

namespace
{

#pragma pack(push, 1)

struct EthernetHeader
{
    std::uint8_t destination[6];
    std::uint8_t source[6];
    std::uint16_t type;
};

struct IPv4Header
{
    std::uint8_t versionIhl;
    std::uint8_t tos;
    std::uint16_t totalLength;
    std::uint16_t identification;
    std::uint16_t flagsFragment;
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t checksum;
    std::uint32_t source;
    std::uint32_t destination;
};

struct TCPHeader
{
    std::uint16_t sourcePort;
    std::uint16_t destinationPort;
    std::uint32_t sequence;
    std::uint32_t acknowledgement;
    std::uint8_t dataOffsetReserved;
    std::uint8_t flags;
    std::uint16_t window;
    std::uint16_t checksum;
    std::uint16_t urgent;
};

struct UDPHeader
{
    std::uint16_t sourcePort;
    std::uint16_t destinationPort;
    std::uint16_t length;
    std::uint16_t checksum;
};

#pragma pack(pop)


/*
 * Convert a captured packet timestamp into a
 * human-readable local timestamp.
 */
std::string timestampFromPacket(
    const pcap_pkthdr* header
)
{
    if (header == nullptr)
    {
        return {};
    }

    const std::time_t seconds =
        static_cast<std::time_t>(
            header->ts.tv_sec
        );

    std::tm localTime{};

    localtime_s(
        &localTime,
        &seconds
    );

    const long milliseconds =
        header->ts.tv_usec / 1000;

    std::ostringstream output;

    output
        << std::put_time(
            &localTime,
            "%Y-%m-%d %H:%M:%S"
        )
        << '.'
        << std::setfill('0')
        << std::setw(3)
        << milliseconds;

    return output.str();
}


/*
 * Normalize a packet filter.
 *
 * Examples:
 *
 *     tcp -> TCP
 *     Tcp -> TCP
 *     UDP -> UDP
 */
std::string normalizeFilter(
    std::string filter
)
{
    std::transform(
        filter.begin(),
        filter.end(),
        filter.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                std::toupper(c)
            );
        }
    );

    return filter;
}


/*
 * Convert an IPv4 address from network byte order
 * into dotted-decimal notation.
 */
std::string ipv4ToString(
    std::uint32_t address
)
{
    IN_ADDR addr{};

    addr.S_un.S_addr = address;

    char buffer[INET_ADDRSTRLEN]{};

    if (
        inet_ntop(
            AF_INET,
            &addr,
            buffer,
            sizeof(buffer)
        ) == nullptr
    )
    {
        return {};
    }

    return buffer;
}


/*
 * Decode an IPv4 packet.
 */
bool decodeIPv4(
    const std::uint8_t* data,
    std::size_t length,
    CapturedPacket& packet
)
{
    if (
        data == nullptr ||
        length < 20
    )
    {
        return false;
    }

    const auto* ip =
        reinterpret_cast<
            const IPv4Header*
        >(data);


    const std::uint8_t version =
        static_cast<std::uint8_t>(
            (ip->versionIhl >> 4) & 0x0F
        );


    const std::size_t headerLength =
        static_cast<std::size_t>(
            ip->versionIhl & 0x0F
        ) * 4;


    if (version != 4)
    {
        return false;
    }


    if (
        headerLength < 20 ||
        headerLength > length
    )
    {
        return false;
    }


    packet.source =
        ipv4ToString(
            ip->source
        );


    packet.destination =
        ipv4ToString(
            ip->destination
        );


    packet.ttl =
        ip->ttl;


    const std::uint8_t* transport =
        data + headerLength;


    const std::size_t transportLength =
        length - headerLength;


    switch (ip->protocol)
    {
        case IPPROTO_TCP:
        {
            packet.protocol = "TCP";


            if (
                transportLength >=
                sizeof(TCPHeader)
            )
            {
                const auto* tcp =
                    reinterpret_cast<
                        const TCPHeader*
                    >(transport);


                const std::size_t tcpHeaderLength =
                    static_cast<std::size_t>(
                        (tcp->dataOffsetReserved >> 4)
                    ) * 4;


                if (
                    tcpHeaderLength >= 20 &&
                    tcpHeaderLength <= transportLength
                )
                {
                    packet.sourcePort =
                        ntohs(
                            tcp->sourcePort
                        );


                    packet.destinationPort =
                        ntohs(
                            tcp->destinationPort
                        );
                }
            }


            packet.decoded = true;

            return true;
        }


        case IPPROTO_UDP:
        {
            packet.protocol = "UDP";


            if (
                transportLength >=
                sizeof(UDPHeader)
            )
            {
                const auto* udp =
                    reinterpret_cast<
                        const UDPHeader*
                    >(transport);


                packet.sourcePort =
                    ntohs(
                        udp->sourcePort
                    );


                packet.destinationPort =
                    ntohs(
                        udp->destinationPort
                    );
            }


            packet.decoded = true;

            return true;
        }


        case IPPROTO_ICMP:
        {
            packet.protocol = "ICMP";

            packet.decoded = true;

            return true;
        }


        default:
        {
            packet.protocol = "IPv4";

            packet.decoded = true;

            return true;
        }
    }
}


/*
 * Decode an Ethernet frame.
 */
bool decodePacket(
    const u_char* data,
    std::size_t length,
    CapturedPacket& packet
)
{
    if (
        data == nullptr ||
        length < sizeof(EthernetHeader)
    )
    {
        return false;
    }


    const auto* ethernet =
        reinterpret_cast<
            const EthernetHeader*
        >(data);


    const std::uint16_t etherType =
        ntohs(
            ethernet->type
        );


    const std::uint8_t* payload =
        data + sizeof(EthernetHeader);


    const std::size_t payloadLength =
        length - sizeof(EthernetHeader);


    switch (etherType)
    {
        /*
         * IPv4
         */
        case 0x0800:
        {
            return decodeIPv4(
                payload,
                payloadLength,
                packet
            );
        }


        /*
         * ARP
         */
        case 0x0806:
        {
            packet.protocol = "ARP";
            packet.decoded = true;

            return true;
        }


        /*
         * IPv6
         */
        case 0x86DD:
        {
            packet.protocol = "IPv6";
            packet.decoded = false;

            return true;
        }


        /*
         * Other Ethernet protocols.
         */
        default:
        {
            packet.protocol = "OTHER";
            packet.decoded = false;

            return true;
        }
    }
}


/*
 * Resolve the SlipNet interface name into the
 * actual Npcap device name.
 *
 * Example:
 *
 *     SlipNet:
 *         Wi-Fi
 *
 *     Windows adapter:
 *         {GUID}
 *
 *     Npcap:
 *         \Device\NPF_{GUID}
 */
std::string resolveNpcapInterface(
    const std::string& requested
)
{
    char errorBuffer[PCAP_ERRBUF_SIZE]{};

    pcap_if_t* devices = nullptr;


    /*
     * Enumerate Npcap devices.
     */
    if (
        pcap_findalldevs(
            &devices,
            errorBuffer
        ) != 0
    )
    {
        return {};
    }


    /*
     * First attempt:
     *
     * Direct match against Npcap device name.
     */
    for (
        pcap_if_t* device = devices;
        device != nullptr;
        device = device->next
    )
    {
        if (
            device->name != nullptr &&
            requested == device->name
        )
        {
            const std::string name =
                device->name;

            pcap_freealldevs(
                devices
            );

            return name;
        }
    }


    /*
     * Second attempt:
     *
     * Match the requested name against the
     * Npcap device description.
     */
    for (
        pcap_if_t* device = devices;
        device != nullptr;
        device = device->next
    )
    {
        if (
            device->description != nullptr &&
            requested == device->description
        )
        {
            const std::string name =
                device->name != nullptr
                    ? device->name
                    : "";

            pcap_freealldevs(
                devices
            );

            return name;
        }
    }


    /*
     * Npcap does not necessarily expose the
     * Windows friendly interface name.
     *
     * For example:
     *
     *     Wi-Fi
     *
     * may appear to Npcap as:
     *
     *     \Device\NPF_{GUID}
     *
     * Therefore obtain the Windows adapter GUID.
     */
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
        pcap_freealldevs(
            devices
        );

        return {};
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
    )
    {
        pcap_freealldevs(
            devices
        );

        return {};
    }


    std::string adapterGuid;


    /*
     * Find the Windows adapter whose friendly
     * name matches the interface requested by
     * SlipNet.
     */
    for (
        auto* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next
    )
    {
        if (
            adapter->FriendlyName == nullptr ||
            adapter->AdapterName == nullptr
        )
        {
            continue;
        }


        std::wstring friendlyName(
            adapter->FriendlyName
        );


        std::string friendly(
            friendlyName.begin(),
            friendlyName.end()
        );


        if (
            friendly == requested
        )
        {
            adapterGuid =
                adapter->AdapterName;

            break;
        }
    }


    if (
        adapterGuid.empty()
    )
    {
        pcap_freealldevs(
            devices
        );

        return {};
    }


    /*
     * Find the corresponding Npcap device.
     */
    for (
        pcap_if_t* device = devices;
        device != nullptr;
        device = device->next
    )
    {
        if (
            device->name == nullptr
        )
        {
            continue;
        }


        const std::string deviceName =
            device->name;


        if (
            deviceName.find(
                adapterGuid
            ) != std::string::npos
        )
        {
            pcap_freealldevs(
                devices
            );

            return deviceName;
        }
    }


    /*
     * No matching Npcap interface.
     */
    pcap_freealldevs(
        devices
    );

    return {};
}


/*
 * Apply a BPF packet filter.
 */
bool applyFilter(
    pcap_t* handle,
    const std::string& filter
)
{
    const std::string normalized =
        normalizeFilter(
            filter
        );


    /*
     * No filter.
     */
    if (
        normalized.empty() ||
        normalized == "ALL"
    )
    {
        return true;
    }


    std::string expression;


    if (
        normalized == "TCP"
    )
    {
        expression = "tcp";
    }
    else if (
        normalized == "UDP"
    )
    {
        expression = "udp";
    }
    else if (
        normalized == "ICMP"
    )
    {
        expression = "icmp";
    }
    else if (
        normalized == "IP"
    )
    {
        expression = "ip";
    }
    else
    {
        return false;
    }


    bpf_program program{};


    if (
        pcap_compile(
            handle,
            &program,
            expression.c_str(),
            1,
            PCAP_NETMASK_UNKNOWN
        ) < 0
    )
    {
        return false;
    }


    const int result =
        pcap_setfilter(
            handle,
            &program
        );


    pcap_freecode(
        &program
    );


    return result == 0;
}

} // namespace


/*
 * Determine whether Npcap is available.
 */
bool packetCaptureAvailable()
{
    char errorBuffer[PCAP_ERRBUF_SIZE]{};

    pcap_if_t* devices = nullptr;


    const int result =
        pcap_findalldevs(
            &devices,
            errorBuffer
        );


    if (
        result != 0
    )
    {
        return false;
    }


    const bool available =
        devices != nullptr;


    if (
        devices != nullptr
    )
    {
        pcap_freealldevs(
            devices
        );
    }


    return available;
}


/*
 * Return the packet capture backend.
 */
std::string packetCaptureBackend()
{
    return "Windows / Npcap";
}


/*
 * Capture network packets.
 */
PacketCaptureResult capturePackets(
    const PacketCaptureConfig& config
)
{
    PacketCaptureResult result;


    result.interfaceName =
        config.interfaceName;


    result.durationSeconds =
        config.durationSeconds;


    result.filter =
        config.filter;


    /*
     * Validate interface.
     */
    if (
        config.interfaceName.empty()
    )
    {
        result.error =
            "Capture interface is empty.";

        return result;
    }


    /*
     * Validate duration.
     */
    if (
        config.durationSeconds <= 0
    )
    {
        result.error =
            "Capture duration must be greater than zero.";

        return result;
    }


    char errorBuffer[PCAP_ERRBUF_SIZE]{};

    pcap_if_t* devices = nullptr;


    /*
     * Enumerate Npcap interfaces.
     */
    if (
        pcap_findalldevs(
            &devices,
            errorBuffer
        ) != 0
    )
    {
        result.error =
            "Npcap interface enumeration failed: " +
            std::string(
                errorBuffer
            );

        return result;
    }


    /*
     * Resolve:
     *
     *     Wi-Fi
     *
     * into:
     *
     *     \Device\NPF_{GUID}
     */
    const std::string npcapInterface =
        resolveNpcapInterface(
            config.interfaceName
        );


    if (
        npcapInterface.empty()
    )
    {
        result.error =
            "Npcap interface not found: " +
            config.interfaceName;

        pcap_freealldevs(
            devices
        );

        return result;
    }


    /*
     * We no longer need the initial interface
     * enumeration here.
     */
    pcap_freealldevs(
        devices
    );


    /*
     * Open the resolved Npcap interface.
     */
    pcap_t* handle =
        pcap_open_live(
            npcapInterface.c_str(),
            65536,
            1,
            250,
            errorBuffer
        );


    if (
        handle == nullptr
    )
    {
        result.error =
            "Npcap could not open interface: " +
            std::string(
                errorBuffer
            );

        return result;
    }


    /*
     * SlipNet currently expects Ethernet frames.
     */
    if (
        pcap_datalink(handle) !=
        DLT_EN10MB
    )
    {
        result.error =
            "Unsupported network datalink. "
            "SlipNet currently requires Ethernet.";

        pcap_close(
            handle
        );

        return result;
    }


    /*
     * Apply requested packet filter.
     */
    if (
        !applyFilter(
            handle,
            config.filter
        )
    )
    {
        result.error =
            "Unable to apply packet filter: " +
            config.filter;

        pcap_close(
            handle
        );

        return result;
    }


    std::cout
        << "[*] Capturing packets... "
        << std::flush;


    /*
     * Capture deadline.
     */
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::seconds(
            config.durationSeconds
        );


    /*
     * Capture packets until the requested
     * duration expires or the maximum packet
     * count is reached.
     */
    while (
        std::chrono::steady_clock::now()
        < deadline
    )
    {
        pcap_pkthdr* header = nullptr;

        const u_char* data = nullptr;


        const int status =
            pcap_next_ex(
                handle,
                &header,
                &data
            );


        /*
         * Timeout.
         */
        if (
            status == 0
        )
        {
            continue;
        }


        /*
         * Capture interrupted.
         */
        if (
            status == PCAP_ERROR_BREAK
        )
        {
            break;
        }


        /*
         * Capture error.
         */
        if (
            status < 0
        )
        {
            result.error =
                "Npcap capture failed: " +
                std::string(
                    pcap_geterr(handle)
                );

            pcap_close(
                handle
            );

            return result;
        }


        if (
            header == nullptr ||
            data == nullptr
        )
        {
            continue;
        }


        CapturedPacket packet;


        packet.timestamp =
            timestampFromPacket(
                header
            );


        packet.length =
            header->caplen;


        result.totalBytes +=
            packet.length;


        decodePacket(
            data,
            packet.length,
            packet
        );


        /*
         * Respect the configured maximum
         * packet count.
         */
        if (
            result.packets.size()
            >= config.maxPackets
        )
        {
            break;
        }


        result.packets.push_back(
            std::move(packet)
        );
    }


    /*
     * Close Npcap capture handle.
     */
    pcap_close(
        handle
    );


    std::cout
        << "done.\n";


    result.success = true;


    return result;
}

} // namespace slipnet::platform

#endif