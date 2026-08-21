#include "network/mac_resolver.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

MacResolution MacResolver::resolve(
    const std::string& ip
) const
{
    MacResolution result;

    result.ip = ip;

    std::ifstream arp(
        "/proc/net/arp"
    );

    if (!arp)
    {
        return result;
    }

    std::string line;

    std::getline(
        arp,
        line
    );

    while (std::getline(arp, line))
    {
        std::istringstream stream(line);

        std::string address;
        std::string hwType;
        std::string flags;
        std::string mac;
        std::string mask;
        std::string device;

        stream
            >> address
            >> hwType
            >> flags
            >> mac
            >> mask
            >> device;

        if (address != ip)
        {
            continue;
        }

        if (mac == "00:00:00:00:00:00")
        {
            continue;
        }

        result.found = true;
        result.mac = normalizeMac(mac);
        result.interfaceName = device;
        result.vendor = lookupVendor(result.mac);

        return result;
    }

    return result;
}


std::string MacResolver::normalizeMac(
    const std::string& mac
) const
{
    std::string result;

    for (char c : mac)
    {
        if (std::isxdigit(
                static_cast<unsigned char>(c)
            ))
        {
            result +=
                static_cast<char>(
                    std::toupper(
                        static_cast<unsigned char>(c)
                    )
                );
        }
    }

    if (result.size() != 12)
    {
        return mac;
    }

    std::string formatted;

    for (std::size_t i = 0; i < result.size(); i += 2)
    {
        if (!formatted.empty())
        {
            formatted += ':';
        }

        formatted +=
            result.substr(i, 2);
    }

    return formatted;
}


std::string MacResolver::lookupVendor(
    const std::string& mac
) const
{
    if (mac.size() < 8)
    {
        return "Unknown";
    }

    std::string oui =
        mac.substr(0, 8);

    /*
     * Common Linux IEEE OUI database locations.
     */
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
                if (std::isxdigit(
                        static_cast<unsigned char>(c)
                    ))
                {
                    normalized +=
                        static_cast<char>(
                            std::toupper(
                                static_cast<unsigned char>(c)
                            )
                        );
                }
                else if (
                    std::isspace(
                        static_cast<unsigned char>(c)
                    )
                )
                {
                    normalized += ' ';
                }
            }

            if (normalized.find(oui) !=
                std::string::npos)
            {
                std::size_t tab =
                    line.find('\t');

                if (tab != std::string::npos)
                {
                    return line.substr(tab + 1);
                }

                std::size_t space =
                    line.find("  ");

                if (space != std::string::npos)
                {
                    return line.substr(space);
                }
            }
        }
    }

    return "Unknown";
}