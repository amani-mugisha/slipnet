#include "monitoring/network_monitor.hpp"

#include <fstream>

#include <iostream>

#include <thread>

#include <chrono>

static uint64_t readCounter(
    const std::string& path
)
{
    std::ifstream file(path);

    uint64_t value = 0;

    file >> value;

    return value;
}

NetworkStats NetworkMonitor::read(
    const std::string& interfaceName
) const
{
    std::string base =
        "/sys/class/net/"
        + interfaceName
        + "/statistics/";

    return
    {
        readCounter(
            base + "rx_bytes"
        ),

        readCounter(
            base + "tx_bytes"
        ),

        readCounter(
            base + "rx_packets"
        ),

        readCounter(
            base + "tx_packets"
        )
    };
}

void NetworkMonitor::monitor(
    const std::string& interfaceName,
    int seconds
) const
{
    NetworkStats previous =
        read(interfaceName);

    for (
        int i = 0;
        i < seconds;
        i++
    )
    {
        std::this_thread::sleep_for(
            std::chrono::seconds(1)
        );

        NetworkStats current =
            read(interfaceName);

        std::cout
            << "RX: "
            << current.receivedBytes
                - previous.receivedBytes
            << " B/s | TX: "
            << current.transmittedBytes
                - previous.transmittedBytes
            << " B/s\n";

        previous = current;
    }
}