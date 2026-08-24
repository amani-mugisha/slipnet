#pragma once

#include <string>
#include <vector>

#include "packet/packet.hpp"

class PacketCapture
{
public:

    std::vector<Packet> capture(
        const std::string& interfaceName,
        int durationSeconds,
        const std::string& filter
    ) const;

private:

    bool matchesFilter(
        const Packet& packet,
        const std::string& filter
    ) const;

    bool saveCapture(
        const std::string& file,
        const std::string& interfaceName,
        int durationSeconds,
        const std::string& filter,
        const std::vector<Packet>& packets
    ) const;
};