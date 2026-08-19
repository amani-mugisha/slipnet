#include "packet/packet_capture.hpp"

#include "cli/signal_handler.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

namespace
{

constexpr const char* CAPTURE_FILE =
    "data/last_capture.txt";


std::string nowTimestamp()
{
    const auto now =
        std::chrono::system_clock::now();

    const auto time =
        std::chrono::system_clock::to_time_t(now);

    std::tm local{};

    localtime_r(
        &time,
        &local
    );

    const auto milliseconds =
        std::chrono::duration_cast<
            std::chrono::milliseconds
        >(
            now.time_since_epoch()
        ) % 1000;

    std::ostringstream output;

    output
        << std::put_time(
            &local,
            "%H:%M:%S"
        )
        << "."
        << std::setfill('0')
        << std::setw(3)
        << milliseconds.count();

    return output.str();
}


std::string ipv4ToString(
    const in_addr& address
)
{
    char buffer[INET_ADDRSTRLEN]{};

    if (
        inet_ntop(
            AF_INET,
            &address,
            buffer,
            sizeof(buffer)
        ) == nullptr
    )
    {
        return "unknown";
    }

    return buffer;
}


std::string normalizeFilter(
    std::string filter
)
{
    for (char& c : filter)
    {
        c = static_cast<char>(
            std::toupper(
                static_cast<unsigned char>(c)
            )
        );
    }

    return filter;
}


bool filterMatches(
    const Packet& packet,
    const std::string& filter
)
{
    if (filter == "ALL")
    {
        return true;
    }

    return packet.protocol == filter;
}


bool decodePacket(
    const unsigned char* buffer,
    std::size_t length,
    Packet& packet
)
{
    if (
        length <
        sizeof(ethhdr) +
        sizeof(iphdr)
    )
    {
        return false;
    }

    const auto* ethernet =
        reinterpret_cast<
            const ethhdr*
        >(buffer);

    if (
        ntohs(
            ethernet->h_proto
        )
        !=
        ETH_P_IP
    )
    {
        return false;
    }

    const auto* ip =
        reinterpret_cast<
            const iphdr*
        >(
            buffer +
            sizeof(ethhdr)
        );

    const std::size_t ipHeaderLength =
        static_cast<std::size_t>(
            ip->ihl
        ) * 4;

    if (
        ipHeaderLength < 20 ||
        length <
        sizeof(ethhdr) +
        ipHeaderLength
    )
    {
        return false;
    }

    in_addr sourceAddress{};
    sourceAddress.s_addr =
        ip->saddr;

    in_addr destinationAddress{};
    destinationAddress.s_addr =
        ip->daddr;

    packet.source =
        ipv4ToString(
            sourceAddress
        );

    packet.destination =
        ipv4ToString(
            destinationAddress
        );

    packet.ttl =
        ip->ttl;

    packet.length =
        static_cast<uint32_t>(
            length
        );

    switch (ip->protocol)
    {
        case IPPROTO_TCP:
        {
            packet.protocol =
                "TCP";

            const std::size_t offset =
                sizeof(ethhdr) +
                ipHeaderLength;

            if (
                length >=
                offset +
                sizeof(tcphdr)
            )
            {
                const auto* tcp =
                    reinterpret_cast<
                        const tcphdr*
                    >(
                        buffer + offset
                    );

                packet.sourcePort =
                    ntohs(
                        tcp->source
                    );

                packet.destinationPort =
                    ntohs(
                        tcp->dest
                    );
            }

            break;
        }

        case IPPROTO_UDP:
        {
            packet.protocol =
                "UDP";

            const std::size_t offset =
                sizeof(ethhdr) +
                ipHeaderLength;

            if (
                length >=
                offset +
                sizeof(udphdr)
            )
            {
                const auto* udp =
                    reinterpret_cast<
                        const udphdr*
                    >(
                        buffer + offset
                    );

                packet.sourcePort =
                    ntohs(
                        udp->source
                    );

                packet.destinationPort =
                    ntohs(
                        udp->dest
                    );
            }

            break;
        }

        case IPPROTO_ICMP:
            packet.protocol =
                "ICMP";
            break;

        default:
            packet.protocol =
                "OTHER";
            break;
    }

    packet.decoded = true;

    return true;
}


void saveCapture(
    const std::string& interfaceName,
    int duration,
    const std::string& filter,
    const std::vector<Packet>& packets
)
{
    std::filesystem::create_directories(
        "data"
    );

    std::ofstream output(
        CAPTURE_FILE,
        std::ios::trunc
    );

    if (!output)
    {
        return;
    }

    uint64_t totalBytes = 0;

    for (const auto& packet : packets)
    {
        totalBytes +=
            packet.length;
    }

    output
        << "SLIPNET_CAPTURE_V2\n"
        << "interface="
        << interfaceName
        << '\n'
        << "duration="
        << duration
        << '\n'
        << "filter="
        << filter
        << '\n'
        << "packets="
        << packets.size()
        << '\n'
        << "bytes="
        << totalBytes
        << "\n\n";

    for (const auto& packet : packets)
    {
        output
            << "[PACKET]\n"
            << "id="
            << packet.id
            << '\n'
            << "timestamp="
            << packet.timestamp
            << '\n'
            << "source="
            << packet.source
            << '\n'
            << "destination="
            << packet.destination
            << '\n'
            << "protocol="
            << packet.protocol
            << '\n'
            << "source_port="
            << packet.sourcePort
            << '\n'
            << "destination_port="
            << packet.destinationPort
            << '\n'
            << "ttl="
            << static_cast<int>(
                packet.ttl
            )
            << '\n'
            << "length="
            << packet.length
            << '\n'
            << "decoded="
            << (
                packet.decoded
                    ? "true"
                    : "false"
            )
            << "\n\n";
    }
}

}


std::vector<Packet>
PacketCapture::capture(
    const std::string& interfaceName,
    int seconds,
    const std::string& filter
) const
{
    std::vector<Packet> packets;

    const std::string normalizedFilter =
        normalizeFilter(filter);

    if (
        interfaceName.empty()
    )
    {
        std::cout
            << "\n[!] Interface is required.\n";

        return packets;
    }

    if (
        seconds <= 0
    )
    {
        std::cout
            << "\n[!] Duration must be greater than zero.\n";

        return packets;
    }

    if (
        normalizedFilter != "ALL" &&
        normalizedFilter != "TCP" &&
        normalizedFilter != "UDP" &&
        normalizedFilter != "ICMP"
    )
    {
        std::cout
            << "\n[!] Unsupported capture filter: "
            << filter
            << "\n"
            << "[*] Supported filters: ALL, TCP, UDP, ICMP\n";

        return packets;
    }

    std::cout
        << "\n"
        << "[*] Preparing packet capture...\n"
        << "[+] Interface: "
        << interfaceName
        << "\n\n";

    std::cout
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: PACKET CAPTURE                                    │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n\n";

    std::cout
        << " Interface     "
        << interfaceName
        << "\n"
        << " Mode          Passive\n"
        << " Duration      "
        << seconds
        << " seconds\n"
        << " Filter        "
        << normalizedFilter
        << "\n\n";

    const int socketFd =
        socket(
            AF_PACKET,
            SOCK_RAW,
            htons(
                ETH_P_ALL
            )
        );

    if (socketFd < 0)
    {
        std::cout
            << "[!] Unable to initialize capture socket.\n"
            << "[*] Raw packet capture normally requires root privileges.\n";

        return packets;
    }

    const unsigned int interfaceIndex =
        if_nametoindex(
            interfaceName.c_str()
        );

    if (interfaceIndex == 0)
    {
        std::cout
            << "[!] Interface '"
            << interfaceName
            << "' does not exist.\n";

        close(socketFd);

        return packets;
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
        std::cout
            << "[!] Failed to bind capture socket to "
            << interfaceName
            << ".\n";

        close(socketFd);

        return packets;
    }

    timeval timeout{};
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    setsockopt(
        socketFd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout)
    );

    std::cout
        << "[+] Capture socket initialized.\n"
        << "[+] Listening on "
        << interfaceName
        << "...\n\n";

    std::cout
        << "┌────────┬────────────────────┬────────────────────┬────────┬────────┐\n"
        << "│ TIME   │ SOURCE             │ DESTINATION        │ PROTO  │ LENGTH │\n"
        << "├────────┼────────────────────┼────────────────────┼────────┼────────┤\n";

    SignalHandler::clearStop();

    const auto start =
        std::chrono::steady_clock::now();

    unsigned char buffer[
        65536
    ];

    uint64_t packetId = 0;

    while (true)
    {
        if (
            SignalHandler::isStopRequested()
        )
        {
            break;
        }

        const auto now =
            std::chrono::steady_clock::now();

        const auto elapsed =
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                now - start
            ).count();

        if (
            elapsed >= seconds
        )
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

        Packet packet;

        if (
            !decodePacket(
                buffer,
                static_cast<std::size_t>(
                    received
                ),
                packet
            )
        )
        {
            continue;
        }

        if (
            !filterMatches(
                packet,
                normalizedFilter
            )
        )
        {
            continue;
        }

        packet.id =
            ++packetId;

        packet.timestamp =
            nowTimestamp();

        packets.push_back(
            packet
        );

        std::cout
            << "│ "
            << std::left
            << std::setw(6)
            << packet.timestamp.substr(
                0,
                5
            )
            << " │ "
            << std::setw(18)
            << packet.source
            << " │ "
            << std::setw(18)
            << packet.destination
            << " │ "
            << std::setw(6)
            << packet.protocol
            << " │ "
            << std::right
            << std::setw(6)
            << packet.length
            << " │\n";
    }

    close(socketFd);

    std::cout
        << "└────────┴────────────────────┴────────────────────┴────────┴────────┘\n\n";

    saveCapture(
        interfaceName,
        seconds,
        normalizedFilter,
        packets
    );

    uint64_t totalBytes = 0;

    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t icmp = 0;
    uint64_t other = 0;

    for (const auto& packet : packets)
    {
        totalBytes +=
            packet.length;

        if (packet.protocol == "TCP")
            ++tcp;
        else if (packet.protocol == "UDP")
            ++udp;
        else if (packet.protocol == "ICMP")
            ++icmp;
        else
            ++other;
    }

    const bool interrupted =
        SignalHandler::isStopRequested();

    std::cout
        << " CAPTURE SUMMARY\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Packets             "
        << packets.size()
        << "\n"
        << " Decoded             "
        << packets.size()
        << "\n"
        << " Bytes               "
        << totalBytes
        << " B\n"
        << " TCP                 "
        << tcp
        << "\n"
        << " UDP                 "
        << udp
        << "\n"
        << " ICMP                "
        << icmp
        << "\n"
        << " Other               "
        << other
        << "\n\n";

    std::cout
        << " STATUS\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Interface            "
        << interfaceName
        << "\n"
        << " Capture              "
        << (
            interrupted
                ? "INTERRUPTED"
                : "COMPLETED"
        )
        << "\n"
        << " Saved                "
        << CAPTURE_FILE
        << "\n";

    if (packets.empty())
    {
        std::cout
            << "\n[!] No matching IPv4 packets were captured.\n";
    }
    else
    {
        std::cout
            << "\n[+] Captured "
            << packets.size()
            << " decoded IPv4 packet";

        if (packets.size() != 1)
            std::cout << "s";

        std::cout
            << ".\n"
            << "[*] Capture stored at "
            << CAPTURE_FILE
            << "\n"
            << "[*] Run pkt|:inspect to inspect the capture.\n";
    }

    SignalHandler::clearStop();

    return packets;
}