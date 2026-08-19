#include "packet/packet_inspector.hpp"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{

struct CaptureData
{
    std::string interfaceName;
    int duration = 0;
    std::string filter;

    std::size_t packetCount = 0;
    std::size_t totalBytes = 0;

    std::vector<Packet> packets;
};


bool parseBool(const std::string& value)
{
    return value == "true" || value == "1";
}


bool loadCapture(
    const std::string& file,
    CaptureData& capture
)
{
    std::ifstream input(file);

    if (!input)
    {
        return false;
    }

    std::string line;
    Packet currentPacket;
    bool insidePacket = false;

    while (std::getline(input, line))
    {
        if (line.empty())
        {
            continue;
        }

        /*
         * ----------------------------------------------------
         * Capture header
         * ----------------------------------------------------
         */

        if (line == "SLIPNET_CAPTURE_V2")
        {
            continue;
        }

        if (line == "[PACKET]")
        {
            if (insidePacket)
            {
                capture.packets.push_back(currentPacket);
            }

            currentPacket = Packet{};
            insidePacket = true;

            continue;
        }


        /*
         * ----------------------------------------------------
         * Key/value parsing
         * ----------------------------------------------------
         */

        const std::size_t separator =
            line.find('=');

        if (separator == std::string::npos)
        {
            continue;
        }

        const std::string key =
            line.substr(
                0,
                separator
            );

        const std::string value =
            line.substr(
                separator + 1
            );


        /*
         * ----------------------------------------------------
         * Capture metadata
         * ----------------------------------------------------
         */

        if (!insidePacket)
        {
            if (key == "interface")
            {
                capture.interfaceName = value;
            }
            else if (key == "duration")
            {
                try
                {
                    capture.duration =
                        std::stoi(value);
                }
                catch (...)
                {
                    capture.duration = 0;
                }
            }
            else if (key == "filter")
            {
                capture.filter = value;
            }
            else if (key == "packets")
            {
                try
                {
                    capture.packetCount =
                        static_cast<std::size_t>(
                            std::stoull(value)
                        );
                }
                catch (...)
                {
                    capture.packetCount = 0;
                }
            }
            else if (key == "bytes")
            {
                try
                {
                    capture.totalBytes =
                        static_cast<std::size_t>(
                            std::stoull(value)
                        );
                }
                catch (...)
                {
                    capture.totalBytes = 0;
                }
            }

            continue;
        }


        /*
         * ----------------------------------------------------
         * Packet fields
         * ----------------------------------------------------
         */

        if (key == "id")
        {
            try
            {
                currentPacket.id =
                    static_cast<std::uint64_t>(
                        std::stoull(value)
                    );
            }
            catch (...)
            {
                currentPacket.id = 0;
            }
        }
        else if (key == "timestamp")
        {
            currentPacket.timestamp = value;
        }
        else if (key == "source")
        {
            currentPacket.source = value;
        }
        else if (key == "destination")
        {
            currentPacket.destination = value;
        }
        else if (key == "protocol")
        {
            currentPacket.protocol = value;
        }
        else if (key == "source_port")
        {
            try
            {
                currentPacket.sourcePort =
                    static_cast<std::uint16_t>(
                        std::stoul(value)
                    );
            }
            catch (...)
            {
                currentPacket.sourcePort = 0;
            }
        }
        else if (key == "destination_port")
        {
            try
            {
                currentPacket.destinationPort =
                    static_cast<std::uint16_t>(
                        std::stoul(value)
                    );
            }
            catch (...)
            {
                currentPacket.destinationPort = 0;
            }
        }
        else if (key == "ttl")
        {
            try
            {
                currentPacket.ttl =
                    static_cast<std::uint8_t>(
                        std::stoul(value)
                    );
            }
            catch (...)
            {
                currentPacket.ttl = 0;
            }
        }
        else if (key == "length")
        {
            try
            {
                currentPacket.length =
                    static_cast<int>(
                        std::stoi(value)
                    );
            }
            catch (...)
            {
                currentPacket.length = 0;
            }
        }
        else if (key == "decoded")
        {
            currentPacket.decoded =
                parseBool(value);
        }
    }


    /*
     * --------------------------------------------------------
     * Store final packet
     * --------------------------------------------------------
     */

    if (insidePacket)
    {
        capture.packets.push_back(
            currentPacket
        );
    }


    /*
     * If metadata is missing or inconsistent,
     * trust the packets actually parsed.
     */

    if (capture.packetCount == 0)
    {
        capture.packetCount =
            capture.packets.size();
    }


    if (capture.totalBytes == 0)
    {
        for (const auto& packet : capture.packets)
        {
            capture.totalBytes +=
                static_cast<std::size_t>(
                    packet.length
                );
        }
    }


    return true;
}


std::string formatBytes(
    std::size_t bytes
)
{
    std::ostringstream output;

    if (bytes >= 1024ULL * 1024ULL)
    {
        output
            << std::fixed
            << std::setprecision(2)
            << static_cast<double>(bytes)
                / (1024.0 * 1024.0)
            << " MB";
    }
    else if (bytes >= 1024ULL)
    {
        output
            << std::fixed
            << std::setprecision(2)
            << static_cast<double>(bytes)
                / 1024.0
            << " KB";
    }
    else
    {
        output
            << bytes
            << " B";
    }

    return output.str();
}


void printPacketRow(
    const Packet& packet
)
{
    std::cout
        << std::left
        << std::setw(7)
        << packet.id

        << std::setw(20)
        << packet.source

        << std::setw(20)
        << packet.destination

        << std::setw(9)
        << packet.protocol

        << std::right
        << std::setw(8)
        << packet.length

        << '\n';
}


} // namespace


void PacketInspector::inspect(
    const Packet& packet
) const
{
    std::cout
        << "\n"
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: PACKET DETAILS                                   │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n\n";


    std::cout
        << " ID\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " "
        << packet.id
        << "\n\n";


    std::cout
        << " TIMESTAMP\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " "
        << packet.timestamp
        << "\n\n";


    std::cout
        << " NETWORK\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Source              "
        << packet.source
        << '\n'

        << " Destination         "
        << packet.destination
        << '\n'

        << " Protocol            "
        << packet.protocol
        << '\n'

        << " Source port         "
        << packet.sourcePort
        << '\n'

        << " Destination port    "
        << packet.destinationPort
        << '\n'

        << " TTL                 "
        << static_cast<int>(packet.ttl)
        << '\n'

        << " Length              "
        << packet.length
        << " bytes\n"

        << " Decoded             "
        << (packet.decoded ? "YES" : "NO")
        << "\n\n";


    std::cout
        << " STATUS\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Decode status       "
        << (packet.decoded ? "VALID" : "UNDECODED")
        << "\n\n";
}


void PacketInspector::inspectFile(
    const std::string& file,
    std::uint64_t packetId
) const
{
    CaptureData capture;


    if (!loadCapture(file, capture))
    {
        std::cout
            << "\n[!] Unable to open capture: "
            << file
            << "\n";

        return;
    }


    /*
     * --------------------------------------------------------
     * Single packet inspection
     * --------------------------------------------------------
     */

    if (packetId > 0)
    {
        for (const auto& packet : capture.packets)
        {
            if (packet.id == packetId)
            {
                inspect(packet);
                return;
            }
        }


        std::cout
            << "\n[!] Packet #"
            << packetId
            << " was not found.\n";


        if (capture.packets.empty())
        {
            std::cout
                << "[*] The capture contains no packets.\n";
        }
        else
        {
            std::cout
                << "[*] Available packets: 1-"
                << capture.packets.back().id
                << "\n";
        }

        return;
    }


    /*
     * --------------------------------------------------------
     * Calculate protocol statistics
     * --------------------------------------------------------
     */

    std::size_t tcpCount = 0;
    std::size_t udpCount = 0;
    std::size_t icmpCount = 0;
    std::size_t otherCount = 0;

    std::size_t decodedCount = 0;

    std::size_t calculatedBytes = 0;


    for (const auto& packet : capture.packets)
    {
        calculatedBytes +=
            static_cast<std::size_t>(
                packet.length
            );


        if (packet.decoded)
        {
            ++decodedCount;
        }


        if (packet.protocol == "TCP")
        {
            ++tcpCount;
        }
        else if (packet.protocol == "UDP")
        {
            ++udpCount;
        }
        else if (packet.protocol == "ICMP")
        {
            ++icmpCount;
        }
        else
        {
            ++otherCount;
        }
    }


    if (capture.totalBytes == 0)
    {
        capture.totalBytes =
            calculatedBytes;
    }


    /*
     * --------------------------------------------------------
     * Main inspection dashboard
     * --------------------------------------------------------
     */

    std::cout
        << "\n"
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: PACKET INSPECTOR                                  │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n\n";


    std::cout
        << " Capture       "
        << file
        << '\n'

        << " Interface     "
        << capture.interfaceName
        << '\n'

        << " Duration      "
        << capture.duration
        << " seconds\n"

        << " Filter        "
        << capture.filter
        << '\n'

        << " Packets       "
        << capture.packets.size()
        << '\n'

        << " Size          "
        << formatBytes(capture.totalBytes)
        << "\n\n";


    /*
     * --------------------------------------------------------
     * Protocol distribution
     * --------------------------------------------------------
     */

    std::cout
        << " PROTOCOL DISTRIBUTION\n"
        << " ────────────────────────────────────────────────────────────\n"

        << " TCP                 "
        << tcpCount
        << '\n'

        << " UDP                 "
        << udpCount
        << '\n'

        << " ICMP                "
        << icmpCount
        << '\n'

        << " OTHER               "
        << otherCount
        << "\n\n";


    /*
     * --------------------------------------------------------
     * Packet index
     * --------------------------------------------------------
     */

    std::cout
        << " PACKET INDEX\n"
        << " ────────────────────────────────────────────────────────────\n";


    if (capture.packets.empty())
    {
        std::cout
            << " No decoded packets available.\n";
    }
    else
    {
        std::cout
            << std::left
            << std::setw(7)
            << "ID"

            << std::setw(20)
            << "SOURCE"

            << std::setw(20)
            << "DESTINATION"

            << std::setw(9)
            << "PROTO"

            << std::right
            << std::setw(8)
            << "LENGTH"

            << '\n';


        std::cout
            << " ────────────────────────────────────────────────────────────\n";


        for (const auto& packet : capture.packets)
        {
            printPacketRow(packet);
        }
    }


    /*
     * --------------------------------------------------------
     * Inspection status
     * --------------------------------------------------------
     */

    std::cout
        << "\n"
        << " INSPECTION STATUS\n"
        << " ────────────────────────────────────────────────────────────\n"

        << " Capture format     SLIPNET_CAPTURE_V2\n"

        << " Decoded packets    "
        << decodedCount
        << '\n'

        << " Total bytes        "
        << formatBytes(capture.totalBytes)
        << '\n'

        << " Status             "
        << (
            capture.packets.empty()
                ? "VALID / EMPTY"
                : "VALID"
        )

        << "\n\n";


    if (!capture.packets.empty())
    {
        std::cout
            << "[+] Inspection completed successfully.\n"
            << "[*] Use pkt|:inspect <ID> for packet-level details.\n";
    }
}