#pragma once

#include <string>
#include <vector>

namespace slipnet::platform {

struct NetworkInterfaceInfo {
    std::string name;
    std::string description;
    std::string ipv4Address;
    std::string netmask;
    std::string macAddress;

    bool up{false};
};

std::vector<NetworkInterfaceInfo> getNetworkInterfaces();

} // namespace slipnet::platform