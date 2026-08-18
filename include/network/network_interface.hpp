#pragma once

#include <string>

class NetworkInterface
{
public:

    NetworkInterface(
        const std::string& name,
        const std::string& ip,
        const std::string& netmask
    );

    const std::string& getName() const;

    const std::string& getIP() const;

    const std::string& getNetmask() const;

private:

    std::string name;

    std::string ip;

    std::string netmask;
};