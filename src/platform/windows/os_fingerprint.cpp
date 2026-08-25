#include "platform/os_fingerprint.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <string>

namespace slipnet::platform
{

OSFingerprintPlatformResult fingerprintHost(
    const std::string& target
)
{
    OSFingerprintPlatformResult result;

    /*
     * --------------------------------------------------------
     * Windows OS fingerprint probe
     * --------------------------------------------------------
     *
     * We intentionally use the native Windows ping command
     * rather than icmpapi.h.
     *
     * This avoids differences between MSVC/MinGW/MSYS2
     * versions of the ICMP API headers.
     *
     * The Windows ping output contains:
     *
     *     TTL=128
     *
     * or another returned TTL value.
     *
     * The common SlipNet layer interprets that TTL.
     */

    if (target.empty())
    {
        return result;
    }


    /*
     * --------------------------------------------------------
     * Build command
     * --------------------------------------------------------
     *
     * -n 1       one echo request
     * -w 1500    1500 ms timeout
     *
     * Redirect stderr so the CLI remains clean.
     */

    const std::string command =
        "ping -n 1 -w 1500 " +
        target +
        " 2>nul";


    /*
     * --------------------------------------------------------
     * Execute ping
     * --------------------------------------------------------
     */

    FILE* pipe =
        _popen(
            command.c_str(),
            "r"
        );

    if (pipe == nullptr)
    {
        return result;
    }


    std::string output;

    char buffer[512]{};

    while (
        std::fgets(
            buffer,
            sizeof(buffer),
            pipe
        ) != nullptr
    )
    {
        output += buffer;
    }


    const int exitCode =
        _pclose(pipe);


    if (exitCode != 0)
    {
        return result;
    }


    /*
     * --------------------------------------------------------
     * Extract TTL
     * --------------------------------------------------------
     *
     * Windows normally produces:
     *
     *     Reply from 10.108.155.140:
     *     bytes=32 time=35ms TTL=128
     *
     * We accept TTL with either upper or lower case.
     */

    std::smatch match;

    const std::regex ttlRegex(
        R"((?:TTL|ttl)\s*=\s*(\d+))"
    );


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


    int ttl = 0;

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


    if (
        ttl <= 0 ||
        ttl > 255
    )
    {
        return result;
    }


    /*
     * --------------------------------------------------------
     * Successful probe
     * --------------------------------------------------------
     */

    result.reachable =
        true;

    result.ttl =
        ttl;

    return result;
}

} // namespace slipnet::platform

#endif
