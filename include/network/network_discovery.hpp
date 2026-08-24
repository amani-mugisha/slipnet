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


    struct LocalNetwork
    {
        std::string interfaceName;
        std::string ip;
        std::string netmask;
        std::string network;

        int prefixLength{24};
    };


    LocalNetwork detectLocalNetwork();


    std::string calculateNetworkAddress(
        const std::string& ip
    );
};