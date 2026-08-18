#pragma once

#include <string>

class Subnet
{
public:

    static std::string calculateNetwork(
        const std::string& ip,
        const std::string& netmask
    );

    static int calculatePrefix(
        const std::string& netmask
    );
};