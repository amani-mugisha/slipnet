#include "platform/ping.hpp"

#ifndef _WIN32

#include <chrono>
#include <cstdlib>
#include <string>

namespace slipnet::platform {

PingResult pingHost(
    const std::string& ip
)
{
    PingResult result;

    const auto start =
        std::chrono::steady_clock::now();

    const std::string command =
        "ping -c 1 -W 1 "
        + ip
        + " > /dev/null 2>&1";

    const int exitCode =
        std::system(
            command.c_str()
        );

    const auto end =
        std::chrono::steady_clock::now();

    result.latencyMs =
        std::chrono::duration<double, std::milli>(
            end - start
        ).count();

    result.reachable =
        (exitCode == 0);

    return result;
}

} // namespace slipnet::platform

#endif