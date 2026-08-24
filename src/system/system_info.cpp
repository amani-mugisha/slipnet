#include "system/system_info.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

#include <sys/utsname.h>
#include <unistd.h>

namespace
{

std::string readFile(const std::string& path)
{
    std::ifstream file(path);

    if (!file)
    {
        return "Unknown";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}


std::string getHostname()
{
    char hostname[256]{};

    if (gethostname(hostname, sizeof(hostname)) == 0)
    {
        return hostname;
    }

    return "Unknown";
}


std::string getOperatingSystem()
{
    std::ifstream file("/etc/os-release");

    if (!file)
    {
        return "Linux";
    }

    std::string line;

    while (std::getline(file, line))
    {
        if (line.rfind("PRETTY_NAME=", 0) == 0)
        {
            std::string value =
                line.substr(
                    std::string("PRETTY_NAME=").length()
                );

            if (
                value.size() >= 2 &&
                value.front() == '"' &&
                value.back() == '"'
            )
            {
                value =
                    value.substr(
                        1,
                        value.size() - 2
                    );
            }

            return value;
        }
    }

    return "Linux";
}


std::string getCpu()
{
    std::ifstream file("/proc/cpuinfo");

    if (!file)
    {
        return "Unknown";
    }

    std::string line;

    while (std::getline(file, line))
    {
        if (line.rfind("model name", 0) == 0)
        {
            const auto separator =
                line.find(':');

            if (separator != std::string::npos)
            {
                return line.substr(
                    separator + 2
                );
            }
        }
    }

    return "Unknown";
}


std::string getMemory()
{
    std::ifstream file("/proc/meminfo");

    if (!file)
    {
        return "Unknown";
    }

    std::string line;

    while (std::getline(file, line))
    {
        if (line.rfind("MemTotal:", 0) == 0)
        {
            std::stringstream stream(line);

            std::string label;
            long long kb = 0;

            stream
                >> label
                >> kb;

            const double gb =
                static_cast<double>(kb)
                / (1024.0 * 1024.0);

            std::ostringstream result;

            result.setf(
                std::ios::fixed
            );

            result.precision(2);

            result
                << gb
                << " GB";

            return result.str();
        }
    }

    return "Unknown";
}


std::string getUptime()
{
    std::ifstream file("/proc/uptime");

    if (!file)
    {
        return "Unknown";
    }

    double seconds = 0.0;

    file >> seconds;

    const long long totalSeconds =
        static_cast<long long>(seconds);

    const long long days =
        totalSeconds / 86400;

    const long long hours =
        (totalSeconds % 86400) / 3600;

    const long long minutes =
        (totalSeconds % 3600) / 60;

    const long long secs =
        totalSeconds % 60;

    std::ostringstream result;

    if (days > 0)
    {
        result << days << "d ";
    }

    result
        << hours << "h "
        << minutes << "m "
        << secs << "s";

    return result.str();
}

}


SystemInfo
SystemInfoProvider::collect() const
{
    SystemInfo info;

    info.hostname =
        getHostname();

    info.operatingSystem =
        getOperatingSystem();

    struct utsname system{};

    if (uname(&system) == 0)
    {
        info.kernel =
            system.release;

        info.architecture =
            system.machine;
    }
    else
    {
        info.kernel =
            "Unknown";

        info.architecture =
            "Unknown";
    }

    info.cpu =
        getCpu();

    info.memory =
        getMemory();

    info.uptime =
        getUptime();

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
        << " OS          "
        << info.operatingSystem
        << "\n"
        << " Kernel      "
        << info.kernel
        << "\n"
        << " Architecture "
        << info.architecture
        << "\n\n";

    std::cout
        << " HARDWARE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " CPU         "
        << info.cpu
        << "\n"
        << " Memory      "
        << info.memory
        << "\n\n";

    std::cout
        << " SYSTEM STATE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Uptime      "
        << info.uptime
        << "\n\n";

    std::cout
        << "[+] System information collected successfully.\n";
}