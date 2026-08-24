#include "platform/packet_capture.hpp"

#ifndef _WIN32

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

#include <cctype>
#include <iostream>
#include <utility>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>


namespace slipnet::platform
{

namespace
{

std::string currentTimestamp()
{
    using namespace std::chrono;

    const auto now = system_clock::now();
    const auto time = system_clock::to_time_t(now);

    std::tm localTime{};
    localtime_r(&time, &localTime);

    // Save the result to a variable
    const auto ms = duration_cast<milliseconds>(
        now.time_since_epoch()
    ) % 1000;

    std::ostringstream output;
    output
        << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S")
        << '.'
        << std::setfill('0')
        << std::setw(3)
        << ms.count();

    return output.str();
}


std::string ipv4ToString(
    std::uint32_t address
)
{
    struct in_addr addr{};

    addr.s_addr =
        address;

    char buffer[
        INET_ADDRSTRLEN
    ]{};

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


bool filterMatches(
    const CapturedPacket& packet,
    const std::string& filter
)
{
    if (
        filter.empty() ||
        filter == "ALL" ||
        filter == "all"
    )
    {
        return true;
    }

    std::string normalized;

    for (char c : filter)
    {
        normalized +=
            static_cast<char>(
                std::toupper(
                    static_cast<unsigned char>(c)
                )
            );
    }

    if (normalized == "TCP")
    {
        return packet.protocol == "TCP";
    }

    if (normalized == "UDP")
    {
        return packet.protocol == "UDP";
    }

    if (normalized == "ICMP")
    {
        return packet.protocol == "ICMP";
    }

    if (normalized == "IP")
    {
        return
            packet.protocol == "TCP" ||
            packet.protocol == "UDP" ||
            packet.protocol == "ICMP";
    }

    return true;
}


bool decodeIPv4(
    const unsigned char* data,
    std::size_t length,
    CapturedPacket& packet
)
{
    if (
        data == nullptr ||
        length < sizeof(iphdr)
    )
    {
        return false;
    }

    const auto* ip =
        reinterpret_cast<
            const iphdr*
        >(data);

    const std::size_t headerLength =
        static_cast<std::size_t>(
            ip->ihl
        ) * 4;

    if (
        headerLength < 20 ||
        length < headerLength
    )
    {
        return false;
    }

    packet.source =
        ipv4ToString(
            ip->saddr
        );

    packet.destination =
        ipv4ToString(
            ip->daddr
        );

    packet.ttl =
        ip->ttl;

    switch (ip->protocol)
    {
        case IPPROTO_TCP:
        {
            packet.protocol = "TCP";

            if (
                length >=
                headerLength +
                sizeof(tcphdr)
            )
            {
                const auto* tcp =
                    reinterpret_cast<
                        const tcphdr*
                    >(
                        data +
                        headerLength
                    );

                packet.sourcePort =
                    ntohs(tcp->source);

                packet.destinationPort =
                    ntohs(tcp->dest);
            }

            packet.decoded = true;

            return true;
        }


        case IPPROTO_UDP:
        {
            packet.protocol = "UDP";

            if (
                length >=
                headerLength +
                sizeof(udphdr)
            )
            {
                const auto* udp =
                    reinterpret_cast<
                        const udphdr*
                    >(
                        data +
                        headerLength
                    );

                packet.sourcePort =
                    ntohs(udp->source);

                packet.destinationPort =
                    ntohs(udp->dest);
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


} // namespace


bool packetCaptureAvailable()
{
    return geteuid() == 0;
}


std::string packetCaptureBackend()
{
    return "Linux AF_PACKET";
}


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


    if (config.interfaceName.empty())
    {
        result.error =
            "Capture interface is empty.";

        return result;
    }


    if (
        config.durationSeconds <= 0
    )
    {
        result.error =
            "Capture duration must be greater than zero.";

        return result;
    }


    if (
        geteuid() != 0
    )
    {
        result.error =
            "Linux packet capture requires root privileges.";

        return result;
    }


    const unsigned int interfaceIndex =
        if_nametoindex(
            config.interfaceName.c_str()
        );

    if (interfaceIndex == 0)
    {
        result.error =
            "Network interface not found: " +
            config.interfaceName;

        return result;
    }


    const int socketFd =
        socket(
            AF_PACKET,
            SOCK_RAW,
            htons(ETH_P_ALL)
        );

    if (socketFd < 0)
    {
        result.error =
            "Unable to create AF_PACKET socket: " +
            std::string(
                std::strerror(errno)
            );

        return result;
    }


    sockaddr_ll address{};

    address.sll_family =
        AF_PACKET;

    address.sll_protocol =
        htons(ETH_P_ALL);

    address.sll_ifindex =
        static_cast<int>(
            interfaceIndex
        );


    if (
        bind(
            socketFd,
            reinterpret_cast<
                sockaddr*
            >(&address),
            sizeof(address)
        ) < 0
    )
    {
        result.error =
            "Unable to bind packet capture socket: " +
            std::string(
                std::strerror(errno)
            );

        close(socketFd);

        return result;
    }


    std::cout
        << "[*] Capturing packets... "
        << std::flush;


    const auto start =
        std::chrono::steady_clock::now();


    const auto deadline =
        start +
        std::chrono::seconds(
            config.durationSeconds
        );


    unsigned char buffer[
        65536
    ];


    while (
        std::chrono::steady_clock::now()
        < deadline
    )
    {
        const auto now =
            std::chrono::steady_clock::now();

        const auto remaining =
            std::chrono::duration_cast<
                std::chrono::milliseconds
            >(
                deadline - now
            );


        timeval timeout{};

        timeout.tv_sec =
            static_cast<long>(
                remaining.count() / 1000
            );

        timeout.tv_usec =
            static_cast<long>(
                (remaining.count() % 1000)
                * 1000
            );


        fd_set readSet;

        FD_ZERO(
            &readSet
        );

        FD_SET(
            socketFd,
            &readSet
        );


        const int ready =
            select(
                socketFd + 1,
                &readSet,
                nullptr,
                nullptr,
                &timeout
            );


        if (ready < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            result.error =
                "Packet capture select() failed: " +
                std::string(
                    std::strerror(errno)
                );

            close(socketFd);

            return result;
        }


        if (ready == 0)
        {
            break;
        }


        const ssize_t received =
            recvfrom(
                socketFd,
                buffer,
                sizeof(buffer),
                0,
                nullptr,
                nullptr
            );


        if (received <= 0)
        {
            continue;
        }


        CapturedPacket packet;

        packet.timestamp =
            currentTimestamp();

        packet.length =
            static_cast<std::size_t>(
                received
            );


        result.totalBytes +=
            packet.length;


        if (
            received >=
            static_cast<ssize_t>(
                sizeof(ethhdr)
            )
        )
        {
            const auto* ethernet =
                reinterpret_cast<
                    const ethhdr*
                >(buffer);


            const std::uint16_t protocol =
                ntohs(
                    ethernet->h_proto
                );


            if (
                protocol == ETH_P_IP
            )
            {
                decodeIPv4(
                    buffer +
                    sizeof(ethhdr),
                    static_cast<std::size_t>(
                        received
                    ) -
                    sizeof(ethhdr),
                    packet
                );
            }
            else if (
                protocol == ETH_P_ARP
            )
            {
                packet.protocol =
                    "ARP";

                packet.decoded =
                    true;
            }
            else if (
                protocol == ETH_P_IPV6
            )
            {
                packet.protocol =
                    "IPv6";

                packet.decoded =
                    false;
            }
            else
            {
                packet.protocol =
                    "OTHER";
            }
        }


        if (
            !filterMatches(
                packet,
                config.filter
            )
        )
        {
            continue;
        }


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


    close(socketFd);


    std::cout
        << "done.\n";


    result.success =
        true;

    return result;
}

} // namespace slipnet::platform

#endif