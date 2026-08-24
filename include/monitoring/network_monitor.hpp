#pragma once

#include <string>

#include "monitoring/network_stats.hpp"

namespace slipnet::monitoring
{

class NetworkMonitor
{
public:

    /*
     * Start continuous network monitoring.
     *
     * Monitoring continues until Ctrl+C.
     */
    bool monitor(
        const std::string& interfaceName,
        int intervalSeconds = 1
    ) const;

    /*
     * Automatically detect the active interface.
     */
    std::string detectActiveInterface() const;

private:

    void displayHeader(
        const std::string& interfaceName,
        int intervalSeconds
    ) const;

    void displaySample(
        const NetworkStats& previous,
        const NetworkStats& current,
        double elapsedSeconds
    ) const;

    void displaySummary(
        const NetworkStats& initial,
        const NetworkStats& final,
        double elapsedSeconds
    ) const;
};

} // namespace slipnet::monitoring