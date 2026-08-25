#pragma once

#include <string>

namespace slipnet::platform
{

struct SessionPlatformInfo
{
    std::string operatingSystem;
    std::string architecture;
    std::string hostname;
};

SessionPlatformInfo getSessionPlatformInfo();

} // namespace slipnet::platform

