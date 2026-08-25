#pragma once

#include <string>

namespace slipnet::platform
{

struct MacPlatformResolution
{
    bool found = false;

    std::string mac;
    std::string vendor;
    std::string interfaceName;
};

MacPlatformResolution resolveMacAddress(
    const std::string& ip
);

} // namespace slipnet::platform