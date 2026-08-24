#include "platform/topology.hpp"

#ifndef _WIN32

#include <cstdio>
#include <string>

namespace slipnet::platform {

LocalTopologyInfo getLocalTopologyInfo()
{
    LocalTopologyInfo info;

    FILE* pipe = popen(
        "ip route get 1.1.1.1 2>/dev/null",
        "r"
    );

    if (pipe == nullptr)
    {
        return info;
    }

    char buffer[512]{};
    std::string output;

    while (fgets(
        buffer,
        sizeof(buffer),
        pipe
    ))
    {
        output += buffer;
    }

    pclose(pipe);

    /*
     * Example:
     *
     * 1.1.1.1 via 10.108.155.140 dev eth1
     * src 10.108.155.233
     */

    const std::size_t viaPos =
        output.find(" via ");

    if (viaPos != std::string::npos)
    {
        const std::size_t start =
            viaPos + 5;

        const std::size_t end =
            output.find(
                ' ',
                start
            );

        if (end != std::string::npos)
        {
            info.gatewayAddress =
                output.substr(
                    start,
                    end - start
                );
        }
    }

    const std::size_t devPos =
        output.find(" dev ");

    if (devPos != std::string::npos)
    {
        const std::size_t start =
            devPos + 5;

        const std::size_t end =
            output.find(
                ' ',
                start
            );

        if (end != std::string::npos)
        {
            info.interfaceName =
                output.substr(
                    start,
                    end - start
                );
        }
    }

    const std::size_t srcPos =
        output.find(" src ");

    if (srcPos != std::string::npos)
    {
        const std::size_t start =
            srcPos + 5;

        const std::size_t end =
            output.find(
                ' ',
                start
            );

        if (end != std::string::npos)
        {
            info.localAddress =
                output.substr(
                    start,
                    end - start
                );
        }
    }

    return info;
}

} // namespace slipnet::platform

#endif