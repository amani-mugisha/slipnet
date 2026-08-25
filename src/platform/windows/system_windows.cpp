#include "platform/system.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <sysinfoapi.h>
#include <intrin.h>

#include <iomanip>
#include <sstream>
#include <string>


namespace
{

std::string getHostname()
{
    char hostname[MAX_COMPUTERNAME_LENGTH + 1]{};

    DWORD length =
        MAX_COMPUTERNAME_LENGTH + 1;

    if (
        GetComputerNameA(
            hostname,
            &length
        )
    )
    {
        return hostname;
    }

    return "Unknown";
}


std::string getArchitecture()
{
#if defined(_M_ARM64)

    return "ARM64";

#elif defined(_M_X64) || defined(_WIN64)

    return "x64";

#elif defined(_M_IX86)

    return "x86";

#elif defined(_M_ARM)

    return "ARM";

#else

    return "Unknown";

#endif
}


std::string getMemory()
{
    MEMORYSTATUSEX memory{};

    memory.dwLength =
        sizeof(memory);

    if (
        GlobalMemoryStatusEx(
            &memory
        )
    )
    {
        const double gb =
            static_cast<double>(
                memory.ullTotalPhys
            )
            / (1024.0 * 1024.0 * 1024.0);

        std::ostringstream result;

        result.setf(std::ios::fixed);
        result.precision(2);

        result << gb << " GB";

        return result.str();
    }

    return "Unknown";
}


std::string getUptime()
{
    const ULONGLONG milliseconds =
        GetTickCount64();

    const unsigned long long totalSeconds =
        milliseconds / 1000ULL;

    const unsigned long long days =
        totalSeconds / 86400ULL;

    const unsigned long long hours =
        (totalSeconds % 86400ULL) / 3600ULL;

    const unsigned long long minutes =
        (totalSeconds % 3600ULL) / 60ULL;

    const unsigned long long seconds =
        totalSeconds % 60ULL;

    std::ostringstream result;

    if (days > 0)
    {
        result << days << "d ";
    }

    result
        << hours << "h "
        << minutes << "m "
        << seconds << "s";

    return result.str();
}


std::string getCpu()
{
    int cpuInfo[4]{};

    __cpuid(
        cpuInfo,
        0
    );

    char vendor[13]{};

    *reinterpret_cast<int*>(
        &vendor[0]
    ) = cpuInfo[1];

    *reinterpret_cast<int*>(
        &vendor[4]
    ) = cpuInfo[3];

    *reinterpret_cast<int*>(
        &vendor[8]
    ) = cpuInfo[2];

    vendor[12] = '\0';

    return vendor;
}


std::string getKernel()
{
    OSVERSIONINFOA versionInfo{};

    versionInfo.dwOSVersionInfoSize =
        sizeof(versionInfo);

#pragma warning(push)
#pragma warning(disable : 4996)

    if (
        GetVersionExA(
            &versionInfo
        )
    )
    {
        std::ostringstream result;

        result
            << versionInfo.dwMajorVersion
            << "."
            << versionInfo.dwMinorVersion
            << "."
            << versionInfo.dwBuildNumber;

        return result.str();
    }

#pragma warning(pop)

    return "Unknown";
}

} // namespace


namespace slipnet::platform
{

SystemPlatformInfo
getSystemPlatformInfo()
{
    SystemPlatformInfo info;

    info.hostname =
        getHostname();

    info.operatingSystem =
        "Windows";

    info.kernel =
        getKernel();

    info.architecture =
        getArchitecture();

    info.cpu =
        getCpu();

    info.memory =
        getMemory();

    info.uptime =
        getUptime();

    return info;
}

} // namespace slipnet::platform

#endif