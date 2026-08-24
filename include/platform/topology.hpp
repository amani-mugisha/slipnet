#pragma once

#include <string>

namespace slipnet::platform {

struct LocalTopologyInfo
{
    std::string interfaceName;
    std::string localAddress;
    std::string gatewayAddress;
};

LocalTopologyInfo getLocalTopologyInfo();

} // namespace slipnet::platform