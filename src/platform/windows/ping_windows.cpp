#include "platform/ping.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

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
        "ping -n 1 -w 1000 "
        + ip
        + " > nul 2>&1";

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