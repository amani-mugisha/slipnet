#pragma once

#include <string>

namespace slipnet::platform
{

struct SystemPlatformInfo
{
    std::string hostname;
    std::string operatingSystem;
    std::string kernel;
    std::string architecture;
    std::string cpu;
    std::string memory;
    std::string uptime;
};

SystemPlatformInfo getSystemPlatformInfo();

} // namespace slipnet::platform