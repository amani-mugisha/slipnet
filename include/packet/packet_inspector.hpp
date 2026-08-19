#pragma once

#include <cstdint>
#include <string>

#include "packet/packet.hpp"

class PacketInspector
{
public:

    void inspect(
        const Packet& packet
    ) const;

    void inspectFile(
        const std::string& file,
        std::uint64_t packetId = 0
    ) const;
};