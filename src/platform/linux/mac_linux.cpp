#include "platform/mac.hpp"

#ifndef _WIN32

#include <fstream>
#include <sstream>
#include <string>


namespace
{

bool isValidMac(
    const std::string& mac
)
{
    if (mac.size() != 17)
    {
        return false;
    }

    for (std::size_t i = 0; i < mac.size(); ++i)
    {
        if (
            i == 2 ||
            i == 5 ||
            i == 8 ||
            i == 11 ||
            i == 14
        )
        {
            if (mac[i] != ':')
            {
                return false;
            }
        }
    }

    return true;
}


std::string
lookupLinuxVendor(
    const std::string& mac
)
{
    if (mac.size() < 8)
    {
        return "Unknown";
    }

    std::string oui =
        mac.substr(0, 8);

    const char* databases[] =
    {
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
        "/usr/share/ieee-data/oui.csv"
    };

    for (const char* path : databases)
    {
        std::ifstream file(path);

        if (!file)
        {
            continue;
        }

        std::string line;

        while (std::getline(file, line))
        {
            std::string normalized;

            for (char c : line)
            {
                if (
                    std::isxdigit(
                        static_cast<unsigned char>(c)
                    )
                )
                {
                    normalized +=
                        static_cast<char>(
                            std::toupper(
                                static_cast<unsigned char>(c)
                            )
                        );
                }
            }

            if (
                normalized.find(oui)
                == std::string::npos
            )
            {
                continue;
            }

            const std::size_t tab =
                line.find('\t');

            if (tab != std::string::npos)
            {
                std::string vendor =
                    line.substr(tab + 1);

                if (!vendor.empty())
                {
                    return vendor;
                }
            }

            const std::size_t space =
                line.find("  ");

            if (space != std::string::npos)
            {
                std::string vendor =
                    line.substr(space);

                if (!vendor.empty())
                {
                    return vendor;
                }
            }
        }
    }

    return "Unknown";
}

} // namespace


namespace slipnet::platform
{

MacPlatformResolution
resolveMacAddress(
    const std::string& ip
)
{
    MacPlatformResolution result;

    std::ifstream arp(
        "/proc/net/arp"
    );

    if (!arp)
    {
        return result;
    }

    std::string line;

    // Skip the header.
    std::getline(
        arp,
        line
    );

    while (std::getline(arp, line))
    {
        std::istringstream stream(line);

        std::string address;
        std::string hardwareType;
        std::string flags;
        std::string mac;
        std::string mask;
        std::string device;

        stream
            >> address
            >> hardwareType
            >> flags
            >> mac
            >> mask
            >> device;

        if (stream.fail())
        {
            continue;
        }

        if (address != ip)
        {
            continue;
        }

        if (
            mac ==
            "00:00:00:00:00:00"
        )
        {
            continue;
        }

        if (!isValidMac(mac))
        {
            continue;
        }

        result.found = true;

        result.mac =
            mac;

        result.interfaceName =
            device;

        result.vendor =
            lookupLinuxVendor(mac);

        return result;
    }

    return result;
}

} // namespace slipnet::platform

#endif