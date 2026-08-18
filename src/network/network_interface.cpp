#include "network/network_interface.hpp"

NetworkInterface::NetworkInterface(
    const std::string& name,
    const std::string& ip,
    const std::string& netmask
)
    : name(name),
      ip(ip),
      netmask(netmask)
{
}

const std::string& NetworkInterface::getName() const
{
    return name;
}

const std::string& NetworkInterface::getIP() const
{
    return ip;
}

const std::string& NetworkInterface::getNetmask() const
{
    return netmask;
}