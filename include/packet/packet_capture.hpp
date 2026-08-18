#pragma once

#include <string>

#include <vector>

#include "packet/packet.hpp"

class PacketCapture
{
public:

    std::vector<Packet> capture(
        const std::string& interfaceName,
        int seconds
    ) const;
};