#pragma once

#include <cstdint>
#include <string>

struct SubnetInfo
{
    bool valid = false;

    std::string input;

    std::string network;
    std::string broadcast;

    std::string firstHost;
    std::string lastHost;

    std::string netmask;
    std::string wildcard;

    int prefix = 0;

    std::uint64_t totalAddresses = 0;
    std::uint64_t usableHosts = 0;
};

class SubnetCalculator
{
public:

    SubnetInfo calculate(
        const std::string& cidr
    ) const;

private:

    std::uint32_t parseIPv4(
        const std::string& ip
    ) const;

    std::string formatIPv4(
        std::uint32_t value
    ) const;
};