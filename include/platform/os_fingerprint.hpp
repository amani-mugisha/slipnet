#pragma once

#include <string>

namespace slipnet::platform
{

struct OSFingerprintPlatformResult
{
    bool reachable = false;
    int ttl = 0;
};

OSFingerprintPlatformResult fingerprintHost(
    const std::string& target
);

} // namespace slipnet::platform