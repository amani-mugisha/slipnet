#include "network/subnet.hpp"

#include <arpa/inet.h>

#include <stdexcept>

static uint32_t convertIP(
    const std::string& address
)
{
    struct in_addr result{};

    if (
        inet_pton(
            AF_INET,
            address.c_str(),
            &result
        ) != 1
    )
    {
        throw std::runtime_error(
            "Invalid IPv4 address"
        );
    }

    return ntohl(result.s_addr);
}

static std::string convertBack(
    uint32_t address
)
{
    struct in_addr result{};

    result.s_addr = htonl(address);

    char buffer[INET_ADDRSTRLEN]{};

    inet_ntop(
        AF_INET,
        &result,
        buffer,
        INET_ADDRSTRLEN
    );

    return std::string(buffer);
}

std::string Subnet::calculateNetwork(
    const std::string& ip,
    const std::string& netmask
)
{
    uint32_t ipAddress = convertIP(ip);

    uint32_t mask = convertIP(netmask);

    uint32_t network = ipAddress & mask;

    return convertBack(network);
}

int Subnet::calculatePrefix(
    const std::string& netmask
)
{
    uint32_t mask = convertIP(netmask);

    int prefix = 0;

    for (int i = 31; i >= 0; --i)
    {
        if ((mask >> i) & 1)
        {
            prefix++;
        }
        else
        {
            break;
        }
    }

    return prefix;
}