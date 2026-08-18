#pragma once

#include <string>

#include <vector>

#include "host/host.hpp"

class HostDiscovery
{
public:

    Host check(
        const std::string& ip
    ) const;

    std::vector<Host> scanSubnet(
        const std::string& cidr
    ) const;

private:

    std::vector<std::string> generateHosts(
        const std::string& cidr
    ) const;
};