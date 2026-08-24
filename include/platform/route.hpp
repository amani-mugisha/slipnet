#pragma once

#include <string>

namespace slipnet::platform
{

struct RouteInfo
{
    std::string interfaceName;
    std::string localIP;
    std::string gateway;

    bool valid{false};
};

RouteInfo getDefaultRoute();

} // namespace slipnet::platform