#include "packet/packet_inspector.hpp"

#include <fstream>

#include <iostream>

void PacketInspector::inspect(
    const Packet& packet
) const
{
    std::cout
        << "Source      : "
        << packet.source
        << '\n';

    std::cout
        << "Destination : "
        << packet.destination
        << '\n';

    std::cout
        << "Protocol    : "
        << packet.protocol
        << '\n';

    std::cout
        << "Length      : "
        << packet.length
        << " bytes\n";
}

void PacketInspector::inspectFile(
    const std::string& file
) const
{
    std::ifstream input(file);

    if (!input)
    {
        std::cout
            << "Unable to open "
            << file
            << '\n';

        return;
    }

    std::string line;

    while (
        std::getline(
            input,
            line
        )
    )
    {
        std::cout
            << line
            << '\n';
    }
}