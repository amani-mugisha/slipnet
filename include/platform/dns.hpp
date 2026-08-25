#pragma once

#include <string>
#include <vector>

namespace slipnet::platform
{

struct DNSPlatformResult
{
    bool success = false;

    std::string canonicalName;

    std::vector<std::string> addresses;

    std::string reverseName;
};

DNSPlatformResult resolveDNS(
    const std::string& input
);

bool isIPAddress(
    const std::string& value
);

} // namespace slipnet::platform