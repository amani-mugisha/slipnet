#pragma once

#include <string>
#include <vector>

#include "port/port.hpp"

class PortScanner
{
public:

    std::vector<Port> scan(
        const std::string& host
    ) const;

    std::vector<Port> scan(
        const std::string& host,
        int startPort,
        int endPort
    ) const;

private:

    bool checkPort(
        const std::string& host,
        int port,
        double& latencyMs
    ) const;
};