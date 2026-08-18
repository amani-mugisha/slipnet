#pragma once

#include <string>

#include "monitoring/network_stats.hpp"

class NetworkMonitor
{
public:

    NetworkStats read(
        const std::string& interfaceName
    ) const;

    void monitor(
        const std::string& interfaceName,
        int seconds
    ) const;
};