#include "network/mac_resolver.hpp"
#include "platform/mac.hpp"

#include <cctype>
#include <string>


MacResolution
MacResolver::resolve(
    const std::string& ip
) const
{
    MacResolution result;

    result.ip = ip;

    const auto platformResult =
        slipnet::platform::resolveMacAddress(ip);

    if (!platformResult.found)
    {
        return result;
    }

    result.found = true;

    result.mac =
        normalizeMac(
            platformResult.mac
        );

    result.vendor =
        platformResult.vendor;

    result.interfaceName =
        platformResult.interfaceName;

    return result;
}


std::string
MacResolver::normalizeMac(
    const std::string& mac
) const
{
    std::string hex;

    for (char c : mac)
    {
        if (
            std::isxdigit(
                static_cast<unsigned char>(c)
            )
        )
        {
            hex +=
                static_cast<char>(
                    std::toupper(
                        static_cast<unsigned char>(c)
                    )
                );
        }
    }

    if (hex.size() != 12)
    {
        return mac;
    }

    std::string formatted;

    formatted.reserve(17);

    for (
        std::size_t i = 0;
        i < hex.size();
        i += 2
    )
    {
        if (!formatted.empty())
        {
            formatted += ':';
        }

        formatted +=
            hex.substr(i, 2);
    }

    return formatted;
}