#include "port/port_scanner.hpp"

#include "cli/signal_handler.hpp"
#include "platform/tcp.hpp"

#include <algorithm>
#include <chrono>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>


namespace
{

constexpr int CONNECTION_TIMEOUT_MS = 2000;
constexpr std::size_t MAX_WORKERS = 64;


/*
 * Common TCP ports used by:
 *
 * port|:scan <host>
 */
const std::vector<int> COMMON_PORTS =
{
    21,      // FTP
    22,      // SSH
    23,      // Telnet
    25,      // SMTP
    53,      // DNS
    80,      // HTTP
    110,     // POP3
    135,     // MS RPC
    139,     // NetBIOS
    143,     // IMAP
    443,     // HTTPS
    445,     // SMB
    3306,    // MySQL
    3389,    // RDP
    5432,    // PostgreSQL
    5900,    // VNC
    6379,    // Redis
    8080,    // HTTP alternate
    8443     // HTTPS alternate
};

}


/*
 * ============================================================
 * Check one TCP port
 * ============================================================
 *
 * IMPORTANT:
 *
 * This file contains NO Linux socket code and NO Windows
 * socket code.
 *
 * All platform-specific networking is handled through:
 *
 *     platform/tcp.hpp
 *
 * Linux:
 *     tcp_linux.cpp
 *
 * Windows:
 *     tcp_windows.cpp
 *
 * This keeps port|:scan portable.
 * ============================================================
 */
bool PortScanner::checkPort(
    const std::string& host,
    int port,
    double& latencyMs
) const
{
    latencyMs = 0.0;


    if (SignalHandler::isStopRequested())
    {
        return false;
    }


    const auto start =
        std::chrono::steady_clock::now();


    slipnet::platform::TcpConnection connection =
        slipnet::platform::tcpConnect(
            host,
            port,
            CONNECTION_TIMEOUT_MS
        );


    const auto end =
        std::chrono::steady_clock::now();


    latencyMs =
        std::chrono::duration<double, std::milli>(
            end - start
        ).count();


    if (!connection.valid)
    {
        return false;
    }


    slipnet::platform::tcpClose(
        connection
    );


    return true;
}


/*
 * ============================================================
 * Scan common ports
 * ============================================================
 */
std::vector<Port>
PortScanner::scan(
    const std::string& host
) const
{
    std::vector<Port> results;


    /*
     * Scan concurrently so the command does not wait for
     * every port sequentially.
     */
    std::vector<std::future<Port>> futures;


    futures.reserve(
        COMMON_PORTS.size()
    );


    for (int port : COMMON_PORTS)
    {
        if (SignalHandler::isStopRequested())
        {
            break;
        }


        futures.push_back(
            std::async(
                std::launch::async,

                [this, &host, port]()
                {
                    double latency = 0.0;


                    const bool open =
                        checkPort(
                            host,
                            port,
                            latency
                        );


                    return Port
                    {
                        port,
                        open,
                        latency
                    };
                }
            )
        );
    }


    /*
     * Collect results.
     */
    for (auto& future : futures)
    {
        if (SignalHandler::isStopRequested())
        {
            break;
        }


        results.push_back(
            future.get()
        );
    }


    /*
     * Keep results deterministic.
     */
    std::sort(
        results.begin(),
        results.end(),

        [](const Port& a, const Port& b)
        {
            return a.number < b.number;
        }
    );


    return results;
}


/*
 * ============================================================
 * Scan custom port range
 * ============================================================
 *
 * Example:
 *
 *     port|:scan 192.168.1.10 1-1024
 *
 * The CLI parser should provide:
 *
 *     startPort
 *     endPort
 * ============================================================
 */
std::vector<Port>
PortScanner::scan(
    const std::string& host,
    int startPort,
    int endPort
) const
{
    std::vector<Port> results;


    /*
     * Sanitize range.
     */
    startPort =
        std::max(
            1,
            startPort
        );


    endPort =
        std::min(
            65535,
            endPort
        );


    if (startPort > endPort)
    {
        return results;
    }


    std::vector<std::future<Port>> futures;

    futures.reserve(
        MAX_WORKERS
    );


    /*
     * Process the range in batches.
     *
     * This prevents thousands of simultaneous sockets.
     */
    for (
        int port = startPort;
        port <= endPort;
        ++port
    )
    {
        if (SignalHandler::isStopRequested())
        {
            break;
        }


        futures.push_back(
            std::async(
                std::launch::async,

                [this, &host, port]()
                {
                    double latency = 0.0;


                    const bool open =
                        checkPort(
                            host,
                            port,
                            latency
                        );


                    return Port
                    {
                        port,
                        open,
                        latency
                    };
                }
            )
        );


        /*
         * Wait once the worker limit is reached.
         */
        if (futures.size() >= MAX_WORKERS)
        {
            for (auto& future : futures)
            {
                if (SignalHandler::isStopRequested())
                {
                    break;
                }


                results.push_back(
                    future.get()
                );
            }


            futures.clear();
        }
    }


    /*
     * Collect remaining workers.
     */
    for (auto& future : futures)
    {
        if (SignalHandler::isStopRequested())
        {
            break;
        }


        results.push_back(
            future.get()
        );
    }


    /*
     * Keep output ordered by port number.
     */
    std::sort(
        results.begin(),
        results.end(),

        [](const Port& a, const Port& b)
        {
            return a.number < b.number;
        }
    );


    return results;
}