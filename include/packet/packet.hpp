#pragma once

#include <cstdint>
#include <string>

struct Packet
{
    std::uint64_t id{0};

    std::string timestamp;

    std::string source;
    std::string destination;

    std::string protocol;

    std::uint16_t sourcePort{0};
    std::uint16_t destinationPort{0};

    std::uint8_t ttl{0};

    int length{0};

    bool decoded{false};
};