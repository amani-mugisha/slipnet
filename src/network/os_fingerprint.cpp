#include "network/os_fingerprint.hpp"

#include <cstdio>
#include <regex>
#include <string>

OSFingerprint OSFingerprinter::fingerprint(
    const std::string& target
) const
{
    OSFingerprint result;

    result.target = target;

    /*
     * Linux ping output commonly contains:
     *
     * ttl=64
     *
     * Windows commonly:
     *
     * TTL=128
     *
     * Network devices often:
     *
     * TTL=255
     *
     * This is a heuristic, not proof.
     */

    std::string command =
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

    char buffer[512];

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

    int ttl;

    try
    {
        ttl =
            std::stoi(
                match[1].str()
            );
    }
    catch (...)
    {
        return result;
    }

    result.ttl = ttl;
    result.detected = true;

    if (ttl <= 64)
    {
        result.operatingSystem =
            "Linux / Unix-like";

        result.confidence =
            ttl == 64
                ? "HIGH"
                : "MEDIUM";
    }
    else if (ttl <= 128)
    {
        result.operatingSystem =
            "Windows";

        result.confidence =
            ttl == 128
                ? "HIGH"
                : "MEDIUM";
    }
    else if (ttl <= 255)
    {
        result.operatingSystem =
            "Network appliance / embedded";

        result.confidence =
            ttl == 255
                ? "HIGH"
                : "LOW";
    }
    else
    {
        result.operatingSystem =
            "Unknown";

        result.confidence =
            "LOW";
    }

    return result;
}