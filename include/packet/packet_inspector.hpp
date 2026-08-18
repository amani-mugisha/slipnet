#pragma once

#include <string>

#include "packet/packet.hpp"

class PacketInspector
{
public:

    void inspect(
        const Packet& packet
    ) const;

    void inspectFile(
        const std::string& file
    ) const;
};