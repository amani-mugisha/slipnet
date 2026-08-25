#include "network/subnet_calculator.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <cctype>
#include <cstdint>
#include <limits>
#include <sstream>


SubnetInfo
SubnetCalculator::calculate(
    const std::string& cidr
) const
{
    SubnetInfo result;

    result.input = cidr;

    std::string ip;
    int prefix = 0;

    if (!parseCIDR(
            cidr,
            ip,
            prefix
        ))
    {
        return result;
    }

    const std::uint32_t address =
        parseIPv4(ip);

    /*
     * parseIPv4() returns zero for failure,
     * but 0.0.0.0 is a valid address.
     */
    if (
        address == 0 &&
        ip != "0.0.0.0"
    )
    {
        return result;
    }

    /*
     * Construct IPv4 netmask safely.
     *
     * /0:
     *     00000000...
     *
     * /32:
     *     FFFFFFFF
     */
    const std::uint32_t mask =
        prefix == 0
            ? 0u
            : 0xFFFFFFFFu << (32 - prefix);

    const std::uint32_t network =
        address & mask;

    const std::uint32_t broadcast =
        network | ~mask;

    const std::uint64_t total =
        static_cast<std::uint64_t>(
            broadcast
        ) -
        static_cast<std::uint64_t>(
            network
        ) +
        1ULL;

    result.valid = true;

    result.prefix =
        prefix;

    result.network =
        formatIPv4(network);

    result.broadcast =
        formatIPv4(broadcast);

    result.netmask =
        formatIPv4(mask);

    result.wildcard =
        formatIPv4(~mask);

    result.totalAddresses =
        total;

    /*
     * Host calculation.
     *
     * /31:
     *     Both addresses can be used as
     *     point-to-point endpoints.
     *
     * /32:
     *     Represents one host.
     *
     * /0 - /30:
     *     Traditional network/broadcast model.
     */
    if (prefix <= 30)
    {
        result.firstHost =
            formatIPv4(
                network + 1
            );

        result.lastHost =
            formatIPv4(
                broadcast - 1
            );

        result.usableHosts =
            total >= 2
                ? total - 2
                : 0;
    }
    else if (prefix == 31)
    {
        result.firstHost =
            formatIPv4(network);

        result.lastHost =
            formatIPv4(broadcast);

        result.usableHosts =
            2;
    }
    else
    {
        result.firstHost =
            result.network;

        result.lastHost =
            result.network;

        result.usableHosts =
            1;
    }

    result.addressType =
        classifyAddress(address);

    return result;
}


/*
 * ------------------------------------------------------------
 * CIDR parsing
 * ------------------------------------------------------------
 */

bool
SubnetCalculator::parseCIDR(
    const std::string& cidr,
    std::string& ip,
    int& prefix
) const
{
    const std::size_t slash =
        cidr.find('/');

    /*
     * CIDR must contain exactly one slash.
     */
    if (
        slash == std::string::npos ||
        slash == 0 ||
        slash == cidr.size() - 1
    )
    {
        return false;
    }

    if (
        cidr.find(
            '/',
            slash + 1
        ) != std::string::npos
    )
    {
        return false;
    }

    ip =
        cidr.substr(
            0,
            slash
        );

    const std::string prefixText =
        cidr.substr(
            slash + 1
        );

    /*
     * Reject whitespace and signs.
     */
    for (char c : prefixText)
    {
        if (
            !std::isdigit(
                static_cast<unsigned char>(c)
            )
        )
        {
            return false;
        }
    }

    return parsePrefix(
        prefixText,
        prefix
    );
}


/*
 * ------------------------------------------------------------
 * Prefix validation
 * ------------------------------------------------------------
 */

bool
SubnetCalculator::parsePrefix(
    const std::string& value,
    int& prefix
) const
{
    if (value.empty())
    {
        return false;
    }

    unsigned long parsed = 0;

    try
    {
        parsed =
            std::stoul(
                value
            );
    }
    catch (...)
    {
        return false;
    }

    if (parsed > 32)
    {
        return false;
    }

    prefix =
        static_cast<int>(
            parsed
        );

    return true;
}


/*
 * ------------------------------------------------------------
 * IPv4 parsing
 * ------------------------------------------------------------
 */

std::uint32_t
SubnetCalculator::parseIPv4(
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


/*
 * ------------------------------------------------------------
 * IPv4 formatting
 * ------------------------------------------------------------
 */

std::string
SubnetCalculator::formatIPv4(
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


/*
 * ------------------------------------------------------------
 * Address classification
 * ------------------------------------------------------------
 */

std::string
SubnetCalculator::classifyAddress(
    std::uint32_t address
) const
{
    /*
     * 0.0.0.0/8
     */
    if (
        (address & 0xFF000000u) == 0x00000000u
    )
    {
        return "Unspecified / Special";
    }

    /*
     * 10.0.0.0/8
     */
    if (
        (address & 0xFF000000u) == 0x0A000000u
    )
    {
        return "Private";
    }

    /*
     * 172.16.0.0/12
     */
    if (
        (address & 0xFFF00000u) == 0xAC100000u
    )
    {
        return "Private";
    }

    /*
     * 192.168.0.0/16
     */
    if (
        (address & 0xFFFF0000u) == 0xC0A80000u
    )
    {
        return "Private";
    }

    /*
     * 127.0.0.0/8
     */
    if (
        (address & 0xFF000000u) == 0x7F000000u
    )
    {
        return "Loopback";
    }

    /*
     * 169.254.0.0/16
     */
    if (
        (address & 0xFFFF0000u) == 0xA9FE0000u
    )
    {
        return "Link-local";
    }

    /*
     * 224.0.0.0/4
     */
    if (
        (address & 0xF0000000u) == 0xE0000000u
    )
    {
        return "Multicast";
    }

    /*
     * 240.0.0.0/4
     */
    if (
        (address & 0xF0000000u) == 0xF0000000u
    )
    {
        return "Reserved";
    }

    return "Public / Global";
}