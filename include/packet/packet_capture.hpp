#pragma once

#include <string>
#include <vector>

#include "packet/packet.hpp"

class PacketCapture
{
public:

    /*
     * Capture packets from a Linux network interface.
     *
     * interfaceName:
     *     Interface such as eth0, eth1.
     *
     * seconds:
     *     Capture duration.
     *
     * filter:
     *     ALL, TCP, UDP or ICMP.
     */
    std::vector<Packet> capture(
        const std::string& interfaceName,
        int seconds,
        const std::string& filter = "ALL"
    ) const;
};