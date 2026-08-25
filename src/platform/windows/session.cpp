#include "platform/session.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

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

    info.operatingSystem =
        "Windows";


    /*
     * --------------------------------------------------------
     * Architecture
     * --------------------------------------------------------
     */

#if defined(_M_ARM64)

    info.architecture =
        "ARM64";

#elif defined(_M_X64) || defined(_WIN64)

    info.architecture =
        "x64";

#elif defined(_M_IX86)

    info.architecture =
        "x86";

#elif defined(_M_ARM)

    info.architecture =
        "ARM";

#else

    info.architecture =
        "Unknown";

#endif

    /*
     * --------------------------------------------------------
     * Hostname
     * --------------------------------------------------------
     */

    char hostname[MAX_COMPUTERNAME_LENGTH + 1]{};

    DWORD hostnameLength =
        MAX_COMPUTERNAME_LENGTH + 1;

    if (
        GetComputerNameA(
            hostname,
            &hostnameLength
        )
    )
    {
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

