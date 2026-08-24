#pragma once

#include <string>

struct SystemInfo
{
    std::string hostname;
    std::string operatingSystem;
    std::string kernel;
    std::string architecture;
    std::string cpu;
    std::string memory;
    std::string uptime;
};

class SystemInfoProvider
{
public:
    SystemInfo collect() const;
    void display(const SystemInfo& info) const;
};