#pragma once

#include <string>

#include "core/network_state.hpp"


class HostScanner
{
public:

    explicit HostScanner(
        NetworkState& state
    );


    bool scan(
        const std::string& ip
    );


private:

    NetworkState& state;


    bool ping(
        const std::string& ip,
        double& latency
    );
};