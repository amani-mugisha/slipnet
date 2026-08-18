#include "port/port_scanner.hpp"

#include <arpa/inet.h>

#include <chrono>

#include <fcntl.h>

#include <future>

#include <netinet/in.h>

#include <sys/select.h>

#include <sys/socket.h>

#include <unistd.h>

#include <vector>

#include "cli/signal_handler.hpp"


bool PortScanner::checkPort(
    const std::string& host,
    int port,
    double& latencyMs
) const
{
    latencyMs = 0.0;


    if (
        SignalHandler::isStopRequested()
    )
    {
        return false;
    }


    int socketFD =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );


    if (socketFD < 0)
    {
        return false;
    }


    sockaddr_in address{};

    address.sin_family = AF_INET;

    address.sin_port =
        htons(
            static_cast<uint16_t>(
                port
            )
        );


    if (
        inet_pton(
            AF_INET,
            host.c_str(),
            &address.sin_addr
        ) != 1
    )
    {
        close(socketFD);

        return false;
    }


    int flags =
        fcntl(
            socketFD,
            F_GETFL,
            0
        );


    fcntl(
        socketFD,
        F_SETFL,
        flags | O_NONBLOCK
    );


    auto start =
        std::chrono::steady_clock::now();


    connect(
        socketFD,
        reinterpret_cast<sockaddr*>(
            &address
        ),
        sizeof(address)
    );


    fd_set writeSet;

    FD_ZERO(&writeSet);

    FD_SET(
        socketFD,
        &writeSet
    );


    timeval timeout{};

    timeout.tv_sec = 0;

    timeout.tv_usec = 500000;


    int result =
        select(
            socketFD + 1,
            nullptr,
            &writeSet,
            nullptr,
            &timeout
        );


    auto end =
        std::chrono::steady_clock::now();


    latencyMs =
        std::chrono::duration<double, std::milli>(
            end - start
        ).count();


    bool open = false;


    if (result > 0)
    {
        int error = 0;

        socklen_t length =
            sizeof(error);


        getsockopt(
            socketFD,
            SOL_SOCKET,
            SO_ERROR,
            &error,
            &length
        );


        open =
            (error == 0);
    }


    close(socketFD);


    return open;
}


std::vector<Port>
PortScanner::scan(
    const std::string& host
) const
{
    /*
        Default common TCP ports.
    */

    const std::vector<int> commonPorts =
    {
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443
    };


    std::vector<Port> results;


    for (int port : commonPorts)
    {
        if (
            SignalHandler::isStopRequested()
        )
        {
            break;
        }


        double latency = 0.0;


        bool open =
            checkPort(
                host,
                port,
                latency
            );


        results.push_back(
            {
                port,
                open,
                latency
            }
        );
    }


    return results;
}


std::vector<Port>
PortScanner::scan(
    const std::string& host,
    int startPort,
    int endPort
) const
{
    std::vector<Port> results;


    if (startPort < 1)
    {
        startPort = 1;
    }


    if (endPort > 65535)
    {
        endPort = 65535;
    }


    if (startPort > endPort)
    {
        return results;
    }


    /*
        Limit concurrent connections.

        This prevents accidentally creating
        thousands of sockets simultaneously.
    */

    constexpr std::size_t MAX_WORKERS = 64;


    std::vector<
        std::future<Port>
    > futures;


    for (
        int port = startPort;
        port <= endPort;
        ++port
    )
    {
        if (
            SignalHandler::isStopRequested()
        )
        {
            break;
        }


        futures.push_back(
            std::async(
                std::launch::async,
                [this, &host, port]()
                {
                    double latency = 0.0;

                    bool open =
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


        if (
            futures.size()
            >= MAX_WORKERS
        )
        {
            for (
                auto& future :
                futures
            )
            {
                if (
                    SignalHandler::isStopRequested()
                )
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
        Collect remaining scans.
    */

    for (
        auto& future :
        futures
    )
    {
        if (
            SignalHandler::isStopRequested()
        )
        {
            break;
        }


        results.push_back(
            future.get()
        );
    }


    return results;
}