#include "network/network_discovery.hpp"

#include "cli/signal_handler.hpp"

#include <chrono>

#include <cstdio>

#include <cstdlib>

#include <future>

#include <iostream>

#include <mutex>

#include <string>

#include <thread>

#include <vector>


NetworkDiscovery::NetworkDiscovery(
    NetworkState& state
)
    : state(state)
{
}


std::string NetworkDiscovery::detectLocalIP()
{
    FILE* pipe = popen(
        "ip route get 1.1.1.1 2>/dev/null",
        "r"
    );


    if (!pipe)
    {
        return "";
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


    std::size_t position =
        output.find("src ");


    if (
        position ==
        std::string::npos
    )
    {
        return "";
    }


    position += 4;


    std::size_t end =
        output.find(
            ' ',
            position
        );


    if (
        end ==
        std::string::npos
    )
    {
        end = output.length();
    }


    return output.substr(
        position,
        end - position
    );
}


std::string NetworkDiscovery::calculateNetworkPrefix(
    const std::string& ip
)
{
    std::size_t first =
        ip.find('.');


    if (
        first ==
        std::string::npos
    )
    {
        return "";
    }


    std::size_t second =
        ip.find(
            '.',
            first + 1
        );


    if (
        second ==
        std::string::npos
    )
    {
        return "";
    }


    std::size_t third =
        ip.find(
            '.',
            second + 1
        );


    if (
        third ==
        std::string::npos
    )
    {
        return "";
    }


    return ip.substr(
        0,
        third + 1
    );
}


bool NetworkDiscovery::checkHost(
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


bool NetworkDiscovery::discover()
{
    state.clear();


    std::cout
        << "\n[*] Detecting local network...\n";


    std::string localIP =
        detectLocalIP();


    if (localIP.empty())
    {
        std::cout
            << "[!] Could not determine local IP.\n";

        return false;
    }


    std::string prefix =
        calculateNetworkPrefix(
            localIP
        );


    if (prefix.empty())
    {
        std::cout
            << "[!] Could not determine network.\n";

        return false;
    }


    std::cout
        << "[+] Local IP : "
        << localIP
        << "\n";


    std::cout
        << "[+] Network  : "
        << prefix
        << "0/24\n";


    std::cout
        << "[*] Scanning hosts concurrently...\n";


    /*
     * Instead of:
     *
     * host 1 → wait
     * host 2 → wait
     * host 3 → wait
     *
     * we launch several checks simultaneously.
     */


    std::vector<std::future<bool>> tasks;

    std::vector<std::string> addresses;

    std::vector<double> latencies;


    addresses.reserve(254);

    latencies.resize(254);


    for (int host = 1; host <= 254; ++host)
    {
        addresses.push_back(
            prefix +
            std::to_string(host)
        );
    }


    std::size_t completed = 0;


    /*
     * Limit the number of simultaneous
     * operations to avoid creating hundreds
     * of processes at once.
     */

    const std::size_t MAX_CONCURRENT = 32;


    for (
        std::size_t i = 0;
        i < addresses.size();
        ++i
    )
    {
        if (
            SignalHandler::isStopRequested()
        )
        {
            std::cout
                << "\n[!] Discovery interrupted.\n";

            return false;
        }


        tasks.push_back(
            std::async(
                std::launch::async,
                [this, &addresses, &latencies, i]()
                {
                    return checkHost(
                        addresses[i],
                        latencies[i]
                    );
                }
            )
        );


        /*
         * Once the worker pool reaches
         * the limit, collect the result.
         */

        if (
            tasks.size() >=
            MAX_CONCURRENT
        )
        {
            for (
                std::size_t j = 0;
                j < tasks.size();
                ++j
            )
            {
                bool online =
                    tasks[j].get();


                std::size_t index =
                    completed + j;


                if (online)
                {
                    HostInfo host;

                    host.ip = addresses[index];

                    host.online = true;

                    host.latency_ms =
                        latencies[index];

                    host.status = "ONLINE";

                    state.addHost(host);


                    std::cout
                        << "[+] Host online: "
                        << addresses[index]
                        << " ("
                        << latencies[index]
                        << " ms)"
                        << "\n";
                }
            }


            completed += tasks.size();

            tasks.clear();


            std::cout
                << "[*] Progress: "
                << completed
                << "/254"
                << "\r"
                << std::flush;
        }
    }


    /*
     * Collect the final batch.
     */

    for (
        std::size_t j = 0;
        j < tasks.size();
        ++j
    )
    {
        bool online =
            tasks[j].get();


        std::size_t index =
            completed + j;


        if (online)
        {
            HostInfo host;

            host.ip = addresses[index];

            host.online = true;

            host.latency_ms =
                latencies[index];

            host.status = "ONLINE";

            state.addHost(host);


            std::cout
                << "[+] Host online: "
                << addresses[index]
                << " ("
                << latencies[index]
                << " ms)"
                << "\n";
        }
    }


    std::cout
        << "\n\n[+] Discovery complete.\n";


    std::cout
        << "[+] Hosts discovered: "
        << state.getHostCount()
        << "\n";


    std::cout
        << "[+] Hosts online: "
        << state.getOnlineHostCount()
        << "\n";


    return true;
}