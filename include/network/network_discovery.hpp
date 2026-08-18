#pragma once

#include <string>

#include "core/network_state.hpp"


class NetworkDiscovery
{
public:

    explicit NetworkDiscovery(
        NetworkState& state
    );


    bool discover();


private:

    NetworkState& state;


    std::string detectLocalIP();


    std::string calculateNetworkPrefix(
        const std::string& ip
    );


    bool checkHost(
        const std::string& ip,
        double& latency
    );
};