#include "platform/os_fingerprint.hpp"

#ifndef _WIN32

#include <cstdio>
#include <regex>
#include <string>

namespace slipnet::platform
{

OSFingerprintPlatformResult
fingerprintHost(
    const std::string& target
)
{
    OSFingerprintPlatformResult result;

    /*
     * --------------------------------------------------------
     * Linux ICMP probe
     * --------------------------------------------------------
     */

    const std::string command =
        "ping -c 1 -W 2 " +
        target +
        " 2>/dev/null";

    FILE* pipe =
        popen(
            command.c_str(),
            "r"
        );

    if (!pipe)
    {
        return result;
    }

    char buffer[512]{};

    std::string output;

    while (
        fgets(
            buffer,
            sizeof(buffer),
            pipe
        )
    )
    {
        output += buffer;
    }

    pclose(pipe);


    /*
     * --------------------------------------------------------
     * Extract TTL
     * --------------------------------------------------------
     */

    std::regex ttlRegex(
        R"((?:ttl|TTL)[=|:](\d+))"
    );

    std::smatch match;

    if (
        !std::regex_search(
            output,
            match,
            ttlRegex
        )
    )
    {
        return result;
    }


    try
    {
        result.ttl =
            std::stoi(
                match[1].str()
            );
    }
    catch (...)
    {
        result.ttl = 0;
        return result;
    }


    if (result.ttl <= 0)
    {
        result.ttl = 0;
        return result;
    }

    result.reachable =
        true;

    return result;
}

} // namespace slipnet::platform

#endif