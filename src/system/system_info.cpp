#include "system/system_info.hpp"
#include "platform/system.hpp"

#include <iostream>


SystemInfo
SystemInfoProvider::collect() const
{
    const auto platformInfo =
        slipnet::platform::getSystemPlatformInfo();

    SystemInfo info;

    info.hostname =
        platformInfo.hostname;

    info.operatingSystem =
        platformInfo.operatingSystem;

    info.kernel =
        platformInfo.kernel;

    info.architecture =
        platformInfo.architecture;

    info.cpu =
        platformInfo.cpu;

    info.memory =
        platformInfo.memory;

    info.uptime =
        platformInfo.uptime;

    return info;
}


void
SystemInfoProvider::display(
    const SystemInfo& info
) const
{
    std::cout
        << "\n"
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: SYSTEM INFORMATION                               │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n"
        << "\n";

    std::cout
        << " HOSTNAME\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " " << info.hostname << "\n\n";

    std::cout
        << " OPERATING SYSTEM\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " OS           "
        << info.operatingSystem
        << "\n"
        << " Kernel       "
        << info.kernel
        << "\n"
        << " Architecture "
        << info.architecture
        << "\n\n";

    std::cout
        << " HARDWARE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " CPU          "
        << info.cpu
        << "\n"
        << " Memory       "
        << info.memory
        << "\n\n";

    std::cout
        << " SYSTEM STATE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Uptime       "
        << info.uptime
        << "\n\n";

    std::cout
        << "[+] System information collected successfully.\n";
}