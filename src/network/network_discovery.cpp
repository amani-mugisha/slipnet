#include "network/network_discovery.hpp"

#include "cli/signal_handler.hpp"
#include "platform/network.hpp"

#include "platform/ping.hpp"
#include "platform/network.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>


namespace
{

//------------------------IPv4 helpers---------------------
uint32_t ipToInteger(
    const std::string& ip
)
{
    std::stringstream stream(ip);

    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;

    char dot1;
    char dot2;
    char dot3;

    if (
        !(stream
            >> a
            >> dot1
            >> b
            >> dot2
            >> c
            >> dot3
            >> d)
    )
    {
        return 0;
    }

    if (
        dot1 != '.' ||
        dot2 != '.' ||
        dot3 != '.'
    )
    {
        return 0;
    }

    if (
        a > 255 ||
        b > 255 ||
        c > 255 ||
        d > 255
    )
    {
        return 0;
    }

    return
        (a << 24) |
        (b << 16) |
        (c << 8) |
        d;
}


std::string integerToIP(
    uint32_t value
)
{
    std::ostringstream output;

    output
        << ((value >> 24) & 0xFF)
        << "."
        << ((value >> 16) & 0xFF)
        << "."
        << ((value >> 8) & 0xFF)
        << "."
        << (value & 0xFF);

    return output.str();
}


/*
 * ============================================================
 * Terminal formatting helpers
 * ============================================================
 */

void printSeparator(
    char character = '-',
    int width = 64
)
{
    std::cout
        << std::string(
            width,
            character
        )
        << '\n';
}


void printHeader()
{
    std::cout << '\n';

    printSeparator('=', 64);

    std::cout
        << "                    NETWORK DISCOVERY\n";

    printSeparator('=', 64);

    std::cout << '\n';
}


void printField(
    const std::string& name,
    const std::string& value
)
{
    std::cout
        << "  "
        << std::left
        << std::setw(14)
        << name
        << ": "
        << value
        << '\n';
}

} // namespace

//--------------Constructor-----------
NetworkDiscovery::NetworkDiscovery(
    NetworkState& state
)
    : state(state)
{
}

//---------------------- Detect local network--------------
NetworkDiscovery::LocalNetwork
NetworkDiscovery::detectLocalNetwork()
{
    LocalNetwork result;


    const auto interfaces =
        slipnet::platform::getNetworkInterfaces();


    for (
        const auto& interface :
        interfaces
    )
    {
        if (!interface.up)
        {
            continue;
        }


        if (
            interface.ipv4Address.empty()
        )
        {
            continue;
        }


        if (
            interface.ipv4Address ==
            "127.0.0.1"
        )
        {
            continue;
        }


        result.interfaceName =
            interface.name;


        result.ip =
            interface.ipv4Address;


        result.netmask =
            interface.netmask;


        /*
         * SlipNet v0.1.0 deliberately
         * uses /24 discovery.
         */
        result.prefixLength = 24;


        result.network =
            calculateNetworkAddress(
                result.ip
            );


        return result;
    }


    return result;
}

std::string
NetworkDiscovery::calculateNetworkAddress(
    const std::string& ip
)
{
    const uint32_t ipValue =
        ipToInteger(ip);

    constexpr uint32_t MASK =
        0xFFFFFF00u;


    const uint32_t network =
        ipValue & MASK;


    return integerToIP(
        network
    );
}


//------------------ Network discovery-------------
bool NetworkDiscovery::discover()
{
    state.clear();


    const auto discoveryStart =
        std::chrono::steady_clock::now();


    printHeader();


    std::cout
        << "[*] Detecting active network interface...\n";


    LocalNetwork network =
        detectLocalNetwork();


    if (
        network.ip.empty()
    )
    {
        std::cout
            << "[!] No active IPv4 network interface found.\n";

        return false;
    }

    //-----------------Discovery configuration-----------
    constexpr int PREFIX_LENGTH = 24;

    constexpr std::size_t TOTAL_ADDRESSES = 254;

    constexpr std::size_t MAX_CONCURRENT = 32;


    std::cout << '\n';


    printField(
        "Interface",
        network.interfaceName
    );


    printField(
        "Local IP",
        network.ip
    );


    printField(
        "Scan Scope",
        network.network + "/24"
    );


    printField(
        "Addresses",
        std::to_string(
            TOTAL_ADDRESSES
        )
    );


    printField(
        "Concurrency",
        std::to_string(
            MAX_CONCURRENT
        )
    );


    printField(
        "Mode",
        "Local IPv4 /24 Discovery"
    );


    std::cout << '\n';


    printSeparator();


    std::cout
        << "[*] Discovering active hosts...\n";


    printSeparator();


    //-----------------Generate /24 addresses------------
    const uint32_t networkValue =
        ipToInteger(
            network.network
        );


    const uint32_t firstHost =
        networkValue + 1;


    const uint32_t lastHost =
        networkValue + 254;


    std::vector<std::string>
        addresses;


    addresses.reserve(
        TOTAL_ADDRESSES
    );


    for (
        uint32_t current =
            firstHost;

        current <=
            lastHost;

        ++current
    )
    {
        addresses.push_back(
            integerToIP(
                current
            )
        );
    }


    std::vector<double>
        latencies(
            TOTAL_ADDRESSES,
            0.0
        );


    std::vector<bool>
        online(
            TOTAL_ADDRESSES,
            false
        );

    //------------ Concurrent scanning---------------
    std::vector<
        std::future<bool>
    > tasks;


    std::size_t completed = 0;


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
                << "\n\n[!] Discovery interrupted.\n";

            return false;
        }


        tasks.push_back(
            std::async(
                std::launch::async,

                [this, &addresses, &latencies, i]()
                {
                    const auto result =
                        slipnet::platform::pingHost(
                            addresses[i]
                        );

                    latencies[i] =
                        result.latencyMs;

                    return result.reachable;
                }
            )
        );

        // Process a batch once the
        // concurrency limit is reached.
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
                const std::size_t index =
                    completed + j;


                online[index] =
                    tasks[j].get();
            }


            completed +=
                tasks.size();


            tasks.clear();


            // Live progress.
            const int percentage =
                static_cast<int>(
                    (
                        completed * 100
                    ) /
                    addresses.size()
                );


            std::cout
                << "\r[*] Progress: "
                << std::setw(3)
                << percentage
                << "%  "
                << completed
                << "/"
                << addresses.size()
                << " hosts checked"
                << std::flush;
        }
    }



    //----------------- Final batch--------------
    for (
        std::size_t j = 0;
        j < tasks.size();
        ++j
    )
    {
        const std::size_t index =
            completed + j;


        online[index] =
            tasks[j].get();
    }


    completed +=
        tasks.size();


    std::cout
        << "\r[*] Progress: 100%  "
        << completed
        << "/"
        << addresses.size()
        << " hosts checked"
        << "            \n";

    //Store discovered hosts
    std::size_t onlineCount = 0;


    for (
        std::size_t i = 0;
        i < addresses.size();
        ++i
    )
    {
        if (!online[i])
        {
            continue;
        }


        ++onlineCount;


        HostInfo host;


        host.ip =
            addresses[i];


        host.online =
            true;


        host.latency_ms =
            latencies[i];


        host.status =
            "ONLINE";


        state.addHost(
            host
        );
    }


    //------------ Results table--------------
    std::cout << '\n';

    printSeparator();

    std::cout
        << "  "
        << std::left
        << std::setw(20)
        << "IP Address"
        << std::setw(14)
        << "Status"
        << "Latency"
        << '\n';


    printSeparator();


    for (
        std::size_t i = 0;
        i < addresses.size();
        ++i
    )
    {
        if (!online[i])
        {
            continue;
        }


        std::cout
            << "  "
            << std::left
            << std::setw(20)
            << addresses[i]
            << std::setw(14)
            << "ONLINE";


        std::cout
            << std::fixed
            << std::setprecision(2)
            << latencies[i]
            << " ms"
            << '\n';
    }


    printSeparator();


    //---------------- Summary---------------

    const auto discoveryEnd =
        std::chrono::steady_clock::now();


    const double duration =
        std::chrono::duration<double>(
            discoveryEnd -
            discoveryStart
        ).count();


    const std::size_t offlineCount =
        TOTAL_ADDRESSES -
        onlineCount;


    std::cout
        << "\n"
        << " Discovery Summary\n";


    printSeparator();


    printField(
        "Scope",
        network.network + "/24"
    );


    printField(
        "Addresses",
        std::to_string(
            TOTAL_ADDRESSES
        )
    );


    printField(
        "Online",
        std::to_string(
            onlineCount
        )
    );


    printField(
        "Offline",
        std::to_string(
            offlineCount
        )
    );


    {
        std::ostringstream value;

        value
            << std::fixed
            << std::setprecision(2)
            << duration
            << " s";


        printField(
            "Duration",
            value.str()
        );
    }


    printSeparator();


    std::cout
        << "\n[+] Network discovery completed successfully.\n";


    return true;
}