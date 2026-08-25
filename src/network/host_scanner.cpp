#include "network/host_scanner.hpp"

#include "cli/signal_handler.hpp"
#include "platform/ping.hpp"

#include <iostream>


HostScanner::HostScanner(
    NetworkState& state
)
    : state(state)
{
}


bool HostScanner::ping(
    const std::string& ip,
    double& latency
)
{
    /*
     * Platform-independent interface.
     *
     * Linux:
     *     src/platform/linux/ping_linux.cpp
     *
     * Windows:
     *     src/platform/windows/ping_windows.cpp
     */
    const auto result =
        slipnet::platform::pingHost(
            ip
        );


    latency =
        result.latencyMs;


    return result.reachable;
}


bool HostScanner::scan(
    const std::string& ip
)
{
    if (
        SignalHandler::isStopRequested()
    )
    {
        return false;
    }


    std::cout
        << "\n[*] Checking host: "
        << ip
        << "\n";


    double latency = 0.0;


    const bool online =
        ping(
            ip,
            latency
        );


    HostInfo host;

    host.ip =
        ip;

    host.online =
        online;

    host.latency_ms =
        latency;


    if (online)
    {
        host.status =
            "ONLINE";

        std::cout
            << "[+] Host is ONLINE\n";

        std::cout
            << "[+] Latency: "
            << latency
            << " ms\n";
    }
    else
    {
        host.status =
            "OFFLINE";

        std::cout
            << "[-] Host is OFFLINE\n";
    }


    state.addHost(
        host
    );


    return online;
}