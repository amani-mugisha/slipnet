#pragma once

#include <cstdint>
#include <string>

namespace slipnet::monitoring
{

struct NetworkStats
{
    std::string interfaceName;

    std::string ipv4Address;

    bool up{false};

    std::uint64_t rxPackets{0};
    std::uint64_t txPackets{0};

    std::uint64_t rxBytes{0};
    std::uint64_t txBytes{0};

    std::uint64_t rxErrors{0};
    std::uint64_t txErrors{0};

    std::uint64_t rxDropped{0};
    std::uint64_t txDropped{0};
};

struct NetworkStatsDelta
{
    std::uint64_t rxPackets{0};
    std::uint64_t txPackets{0};

    std::uint64_t rxBytes{0};
    std::uint64_t txBytes{0};

    std::uint64_t rxErrors{0};
    std::uint64_t txErrors{0};

    std::uint64_t rxDropped{0};
    std::uint64_t txDropped{0};

    double rxPacketsPerSecond{0.0};
    double txPacketsPerSecond{0.0};

    double rxBytesPerSecond{0.0};
    double txBytesPerSecond{0.0};
};

} // namespace slipnet::monitoring