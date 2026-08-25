#include "platform/session.hpp"

#ifndef _WIN32

#include <sys/utsname.h>
#include <unistd.h>

#include <cstring>

namespace slipnet::platform
{

SessionPlatformInfo getSessionPlatformInfo()
{
    SessionPlatformInfo info;

    /*
     * --------------------------------------------------------
     * Operating system
     * --------------------------------------------------------
     */

    struct utsname systemInfo{};

    if (uname(&systemInfo) == 0)
    {
        info.operatingSystem =
            systemInfo.sysname;
    }
    else
    {
        info.operatingSystem =
            "Linux";
    }


    /*
     * --------------------------------------------------------
     * Architecture
     * --------------------------------------------------------
     */

    if (uname(&systemInfo) == 0)
    {
        info.architecture =
            systemInfo.machine;
    }
    else
    {
        info.architecture =
            "Unknown";
    }


    /*
     * --------------------------------------------------------
     * Hostname
     * --------------------------------------------------------
     */

    char hostname[256]{};

    if (
        gethostname(
            hostname,
            sizeof(hostname)
        ) == 0
    )
    {
        hostname[
            sizeof(hostname) - 1
        ] = '\0';

        info.hostname =
            hostname;
    }
    else
    {
        info.hostname =
            "Unknown";
    }


    return info;
}

} // namespace slipnet::platform

#endif

