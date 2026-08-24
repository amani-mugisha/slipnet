#pragma once

#include <cstdint>
#include <string>

namespace slipnet::platform
{

struct NetworkStatus
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

NetworkStatus getNetworkStatus(
    const std::string& interfaceName
);

std::string detectActiveInterface();

bool networkStatusAvailable();

} // namespace slipnet::platform