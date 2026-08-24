#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace slipnet::platform
{

struct CapturedPacket
{
    std::string timestamp;

    std::string source;
    std::string destination;

    std::string protocol;

    std::uint16_t sourcePort{0};
    std::uint16_t destinationPort{0};

    std::uint8_t ttl{0};

    std::size_t length{0};

    bool decoded{false};
};


struct PacketCaptureConfig
{
    std::string interfaceName;

    int durationSeconds{10};

    std::string filter{"ALL"};

    std::size_t maxPackets{10000};
};


struct PacketCaptureResult
{
    bool success{false};

    std::string error;

    std::string interfaceName;

    int durationSeconds{0};

    std::string filter;

    std::vector<CapturedPacket> packets;

    std::size_t totalBytes{0};
};


PacketCaptureResult capturePackets(
    const PacketCaptureConfig& config
);


bool packetCaptureAvailable();


std::string packetCaptureBackend();

} // namespace slipnet::platform