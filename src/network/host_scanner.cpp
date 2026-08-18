#include "network/host_scanner.hpp"

#include "cli/signal_handler.hpp"

#include <chrono>

#include <cstdlib>

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
    auto start =
        std::chrono::steady_clock::now();


    std::string command =
        "ping -c 1 -W 1 "
        + ip
        + " > /dev/null 2>&1";


    int result =
        std::system(
            command.c_str()
        );


    auto end =
        std::chrono::steady_clock::now();


    latency =
        std::chrono::duration<double, std::milli>(
            end - start
        ).count();


    return result == 0;
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


    bool online =
        ping(
            ip,
            latency
        );


    HostInfo host;

    host.ip = ip;

    host.online = online;

    host.latency_ms = latency;


    if (online)
    {
        host.status = "ONLINE";

        std::cout
            << "[+] Host is ONLINE\n";

        std::cout
            << "[+] Latency: "
            << latency
            << " ms\n";
    }
    else
    {
        host.status = "OFFLINE";

        std::cout
            << "[-] Host is OFFLINE\n";
    }


    state.addHost(host);


    return online;
}