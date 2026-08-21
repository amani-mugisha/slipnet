#pragma once

#include <string>

struct MacResolution
{
    bool found = false;

    std::string ip;
    std::string mac;
    std::string vendor;
    std::string interfaceName;
};

class MacResolver
{
public:

    MacResolution resolve(
        const std::string& ip
    ) const;

private:

    std::string normalizeMac(
        const std::string& mac
    ) const;

    std::string lookupVendor(
        const std::string& mac
    ) const;
};