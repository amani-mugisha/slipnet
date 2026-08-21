#include "network/subnet_calculator.hpp"

#include <arpa/inet.h>

#include <cstdint>
#include <sstream>

SubnetInfo SubnetCalculator::calculate(
    const std::string& cidr
) const
{
    SubnetInfo result;

    result.input = cidr;

    const std::size_t slash =
        cidr.find('/');

    if (slash == std::string::npos)
    {
        return result;
    }

    const std::string ip =
        cidr.substr(0, slash);

    const std::string prefixText =
        cidr.substr(slash + 1);

    int prefix;

    try
    {
        prefix =
            std::stoi(prefixText);
    }
    catch (...)
    {
        return result;
    }

    if (prefix < 0 || prefix > 32)
    {
        return result;
    }

    std::uint32_t address =
        parseIPv4(ip);

    if (address == 0 && ip != "0.0.0.0")
    {
        return result;
    }

    std::uint32_t mask =
        prefix == 0
            ? 0
            : 0xFFFFFFFFu << (32 - prefix);

    std::uint32_t network =
        address & mask;

    std::uint32_t broadcast =
        network | ~mask;

    result.valid = true;
    result.prefix = prefix;

    result.network =
        formatIPv4(network);

    result.broadcast =
        formatIPv4(broadcast);

    result.netmask =
        formatIPv4(mask);

    result.wildcard =
        formatIPv4(~mask);

    if (prefix <= 30)
    {
        result.firstHost =
            formatIPv4(network + 1);

        result.lastHost =
            formatIPv4(broadcast - 1);

        result.totalAddresses =
            static_cast<std::uint64_t>(
                broadcast
            ) -
            static_cast<std::uint64_t>(
                network
            ) +
            1;

        result.usableHosts =
            result.totalAddresses - 2;
    }
    else
    {
        result.firstHost =
            result.network;

        result.lastHost =
            result.broadcast;

        result.totalAddresses =
            static_cast<std::uint64_t>(
                broadcast
            ) -
            static_cast<std::uint64_t>(
                network
            ) +
            1;

        result.usableHosts =
            result.totalAddresses;
    }

    return result;
}


std::uint32_t SubnetCalculator::parseIPv4(
    const std::string& ip
) const
{
    in_addr address{};

    if (
        inet_pton(
            AF_INET,
            ip.c_str(),
            &address
        ) != 1
    )
    {
        return 0;
    }

    return ntohl(
        address.s_addr
    );
}


std::string SubnetCalculator::formatIPv4(
    std::uint32_t value
) const
{
    in_addr address{};

    address.s_addr =
        htonl(value);

    char buffer[INET_ADDRSTRLEN]{};

    if (
        inet_ntop(
            AF_INET,
            &address,
            buffer,
            sizeof(buffer)
        ) == nullptr
    )
    {
        return {};
    }

    return buffer;
}