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

    std::string addressType;

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

    bool parseCIDR(
        const std::string& cidr,
        std::string& ip,
        int& prefix
    ) const;

    bool parsePrefix(
        const std::string& value,
        int& prefix
    ) const;

    std::uint32_t parseIPv4(
        const std::string& ip
    ) const;

    std::string formatIPv4(
        std::uint32_t value
    ) const;

    std::string classifyAddress(
        std::uint32_t address
    ) const;
};