#include "packet/packet_capture.hpp"

#include "platform/packet_capture.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace
{

std::string toUpper(
    std::string value
)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                std::toupper(c)
            );
        }
    );

    return value;
}


std::string sanitize(
    const std::string& value
)
{
    std::string result;

    for (char c : value)
    {
        if (
            c == '\n' ||
            c == '\r' ||
            c == '='
        )
        {
            result += '_';
        }
        else
        {
            result += c;
        }
    }

    return result;
}


std::string makeOutputFile()
{
    const auto now =
        std::chrono::system_clock::now();

    const std::time_t time =
        std::chrono::system_clock::to_time_t(now);

    std::tm localTime{};

#ifdef _WIN32
    localtime_s(
        &localTime,
        &time
    );
#else
    localtime_r(
        &time,
        &localTime
    );
#endif

    std::ostringstream output;

    output
        << "slipnet_capture_"
        << std::put_time(
            &localTime,
            "%Y%m%d_%H%M%S"
        )
        << ".slipcap";

    return output.str();
}

} // namespace


bool PacketCapture::matchesFilter(
    const Packet& packet,
    const std::string& filter
) const
{
    const std::string normalized =
        toUpper(filter);

    if (
        normalized.empty() ||
        normalized == "ALL"
    )
    {
        return true;
    }

    if (
        normalized == "TCP" ||
        normalized == "UDP" ||
        normalized == "ICMP"
    )
    {
        return toUpper(packet.protocol)
            == normalized;
    }

    return false;
}


bool PacketCapture::saveCapture(
    const std::string& file,
    const std::string& interfaceName,
    int durationSeconds,
    const std::string& filter,
    const std::vector<Packet>& packets
) const
{
    std::ofstream output(
        file,
        std::ios::out |
        std::ios::trunc
    );

    if (!output)
    {
        return false;
    }

    std::size_t totalBytes = 0;

    for (const auto& packet : packets)
    {
        if (packet.length > 0)
        {
            totalBytes +=
                static_cast<std::size_t>(
                    packet.length
                );
        }
    }

    output
        << "SLIPNET_CAPTURE_V2\n"
        << "interface="
        << sanitize(interfaceName)
        << '\n'
        << "duration="
        << durationSeconds
        << '\n'
        << "filter="
        << sanitize(filter)
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
            << sanitize(packet.timestamp)
            << '\n'

            << "source="
            << sanitize(packet.source)
            << '\n'

            << "destination="
            << sanitize(packet.destination)
            << '\n'

            << "protocol="
            << sanitize(packet.protocol)
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

    return output.good();
}


std::vector<Packet> PacketCapture::capture(
    const std::string& interfaceName,
    int durationSeconds,
    const std::string& filter
) const
{
    std::vector<Packet> packets;

    if (interfaceName.empty())
    {
        std::cout
            << "[!] Capture interface is empty.\n";

        return packets;
    }

    if (
        durationSeconds <= 0 ||
        durationSeconds > 86400
    )
    {
        std::cout
            << "[!] Capture duration must be between "
            << "1 and 86400 seconds.\n";

        return packets;
    }

    const std::string normalizedFilter =
        toUpper(filter);

    if (
        normalizedFilter != "ALL" &&
        normalizedFilter != "TCP" &&
        normalizedFilter != "UDP" &&
        normalizedFilter != "ICMP"
    )
    {
        std::cout
            << "[!] Unsupported packet filter: "
            << filter
            << "\n"
            << "[*] Supported filters: ALL, TCP, UDP, ICMP\n";

        return packets;
    }

    if (
        !slipnet::platform::packetCaptureAvailable()
    )
    {
        std::cout
            << "\n[!] Packet capture backend is unavailable.\n"
            << "[!] Backend: "
            << slipnet::platform::packetCaptureBackend()
            << '\n';

#ifdef _WIN32
        std::cout
            << "[*] Install Npcap with WinPcap compatibility enabled.\n";
#else
        std::cout
            << "[*] Run SlipNet with sufficient privileges.\n";
#endif

        return packets;
    }

    slipnet::platform::PacketCaptureConfig config;

    config.interfaceName =
        interfaceName;

    config.durationSeconds =
        durationSeconds;

    config.filter =
        normalizedFilter;

    config.maxPackets =
        10000;

    std::cout
        << "\n[*] Starting packet capture...\n"
        << "\n"
        << "  Interface : "
        << interfaceName
        << '\n'
        << "  Duration  : "
        << durationSeconds
        << " seconds\n"
        << "  Filter    : "
        << normalizedFilter
        << '\n'
        << "  Backend   : "
        << slipnet::platform::packetCaptureBackend()
        << "\n\n";

    const auto result =
        slipnet::platform::capturePackets(
            config
        );

    if (!result.success)
    {
        std::cout
            << "\n[!] Packet capture failed.\n"
            << "[!] "
            << result.error
            << '\n';

        return packets;
    }

    std::uint64_t packetId = 1;

    for (const auto& captured :
         result.packets)
    {
        Packet packet{};

        packet.id =
            packetId++;

        packet.timestamp =
            captured.timestamp;

        packet.source =
            captured.source;

        packet.destination =
            captured.destination;

        packet.protocol =
            captured.protocol;

        packet.sourcePort =
            captured.sourcePort;

        packet.destinationPort =
            captured.destinationPort;

        packet.ttl =
            captured.ttl;

        packet.length =
            static_cast<int>(
                captured.length
            );

        packet.decoded =
            captured.decoded;

        if (
            matchesFilter(
                packet,
                normalizedFilter
            )
        )
        {
            packets.push_back(
                std::move(packet)
            );
        }
    }

    const std::string outputFile =
        makeOutputFile();

    if (
        !saveCapture(
            outputFile,
            interfaceName,
            durationSeconds,
            normalizedFilter,
            packets
        )
    )
    {
        std::cout
            << "\n[!] Failed to write capture file:\n"
            << "    "
            << outputFile
            << '\n';

        return packets;
    }

    std::cout
        << "\n"
        << "------------------------------------------------------------\n"
        << " Capture Summary\n"
        << "------------------------------------------------------------\n"
        << "  Interface : "
        << result.interfaceName
        << '\n'
        << "  Duration  : "
        << result.durationSeconds
        << " seconds\n"
        << "  Filter    : "
        << result.filter
        << '\n'
        << "  Packets   : "
        << packets.size()
        << '\n'
        << "  Bytes     : "
        << result.totalBytes
        << '\n'
        << "  Output    : "
        << outputFile
        << '\n'
        << "------------------------------------------------------------\n"
        << "\n"
        << "[+] Packet capture completed successfully.\n";

    return packets;
}