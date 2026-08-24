#include "monitoring/network_monitor.hpp"

#include "cli/signal_handler.hpp"
#include "platform/network_status.hpp"

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <thread>

namespace slipnet::monitoring
{

namespace
{

NetworkStats readStats(
    const std::string& interfaceName
)
{
    const auto status =
        slipnet::platform::getNetworkStatus(
            interfaceName
        );

    NetworkStats stats;

    stats.interfaceName =
        status.interfaceName;

    stats.ipv4Address =
        status.ipv4Address;

    stats.up =
        status.up;

    stats.rxPackets =
        status.rxPackets;

    stats.txPackets =
        status.txPackets;

    stats.rxBytes =
        status.rxBytes;

    stats.txBytes =
        status.txBytes;

    stats.rxErrors =
        status.rxErrors;

    stats.txErrors =
        status.txErrors;

    stats.rxDropped =
        status.rxDropped;

    stats.txDropped =
        status.txDropped;

    return stats;
}


std::uint64_t counterDelta(
    std::uint64_t current,
    std::uint64_t previous
)
{
    /*
     * Network counters can reset when an interface
     * restarts or reconnects.
     *
     * Never allow unsigned underflow.
     */
    if (current < previous)
    {
        return current;
    }

    return current - previous;
}


NetworkStatsDelta calculateDelta(
    const NetworkStats& previous,
    const NetworkStats& current,
    double elapsedSeconds
)
{
    NetworkStatsDelta result;

    if (elapsedSeconds <= 0.0)
    {
        return result;
    }

    result.rxPackets =
        counterDelta(
            current.rxPackets,
            previous.rxPackets
        );

    result.txPackets =
        counterDelta(
            current.txPackets,
            previous.txPackets
        );

    result.rxBytes =
        counterDelta(
            current.rxBytes,
            previous.rxBytes
        );

    result.txBytes =
        counterDelta(
            current.txBytes,
            previous.txBytes
        );

    result.rxErrors =
        counterDelta(
            current.rxErrors,
            previous.rxErrors
        );

    result.txErrors =
        counterDelta(
            current.txErrors,
            previous.txErrors
        );

    result.rxDropped =
        counterDelta(
            current.rxDropped,
            previous.rxDropped
        );

    result.txDropped =
        counterDelta(
            current.txDropped,
            previous.txDropped
        );

    result.rxPacketsPerSecond =
        static_cast<double>(
            result.rxPackets
        ) / elapsedSeconds;

    result.txPacketsPerSecond =
        static_cast<double>(
            result.txPackets
        ) / elapsedSeconds;

    result.rxBytesPerSecond =
        static_cast<double>(
            result.rxBytes
        ) / elapsedSeconds;

    result.txBytesPerSecond =
        static_cast<double>(
            result.txBytes
        ) / elapsedSeconds;

    return result;
}


double bytesToKB(
    double bytes
)
{
    return bytes / 1024.0;
}


double bytesToMB(
    double bytes
)
{
    return bytes / (1024.0 * 1024.0);
}

} // namespace


std::string NetworkMonitor::detectActiveInterface() const
{
    return slipnet::platform::detectActiveInterface();
}


void NetworkMonitor::displayHeader(
    const std::string& interfaceName,
    int intervalSeconds
) const
{
    const auto stats =
        readStats(interfaceName);

    std::cout
        << "------------------------------------------------------------\n"
        << " Interface       : "
        << interfaceName
        << '\n'
        << " IPv4 Address    : "
        << (
            stats.ipv4Address.empty()
                ? "N/A"
                : stats.ipv4Address
        )
        << '\n'
        << " Status          : "
        << (
            stats.up
                ? "UP"
                : "DOWN"
        )
        << '\n'
        << " Interval        : "
        << intervalSeconds
        << " second(s)\n"
        << " Mode            : Continuous\n"
        << " Stop            : Ctrl+C\n"
        << "------------------------------------------------------------\n"
        << '\n'
        << std::left
        << std::setw(12) << "TIME"
        << std::right
        << std::setw(14) << "RX PKTS"
        << std::setw(14) << "TX PKTS"
        << std::setw(16) << "RX KB/s"
        << std::setw(16) << "TX KB/s"
        << '\n'
        << "------------------------------------------------------------\n";
}


void NetworkMonitor::displaySample(
    const NetworkStats& previous,
    const NetworkStats& current,
    double elapsedSeconds
) const
{
    const auto stats =
        calculateDelta(
            previous,
            current,
            elapsedSeconds
        );

    const auto now =
        std::chrono::system_clock::now();

    const std::time_t time =
        std::chrono::system_clock::to_time_t(
            now
        );

    std::tm localTime{};

#ifdef _WIN32

    localtime_s(
        &localTime,
        &time
    );

#else

    localtime_r(
        &time,
        &localTime
    );

#endif

    std::cout
        << std::put_time(
            &localTime,
            "%H:%M:%S"
        )
        << std::right
        << std::setw(14)
        << stats.rxPackets
        << std::setw(14)
        << stats.txPackets
        << std::setw(16)
        << std::fixed
        << std::setprecision(2)
        << bytesToKB(
            stats.rxBytesPerSecond
        )
        << std::setw(16)
        << bytesToKB(
            stats.txBytesPerSecond
        )
        << '\n';

    std::cout.flush();
}


void NetworkMonitor::displaySummary(
    const NetworkStats& initial,
    const NetworkStats& final,
    double elapsedSeconds
) const
{
    const auto stats =
        calculateDelta(
            initial,
            final,
            elapsedSeconds
        );

    std::cout
        << "\n"
        << "============================================================\n"
        << "                    MONITOR SUMMARY\n"
        << "============================================================\n"
        << '\n'
        << " Interface       : "
        << final.interfaceName
        << '\n'
        << " IPv4 Address    : "
        << (
            final.ipv4Address.empty()
                ? "N/A"
                : final.ipv4Address
        )
        << '\n'
        << " Final Status    : "
        << (
            final.up
                ? "UP"
                : "DOWN"
        )
        << '\n'
        << " Duration        : "
        << std::fixed
        << std::setprecision(2)
        << elapsedSeconds
        << " seconds\n"
        << '\n'
        << " RX Packets      : "
        << stats.rxPackets
        << '\n'
        << " TX Packets      : "
        << stats.txPackets
        << '\n'
        << " RX Data         : "
        << bytesToMB(
            static_cast<double>(
                stats.rxBytes
            )
        )
        << " MB\n"
        << " TX Data         : "
        << bytesToMB(
            static_cast<double>(
                stats.txBytes
            )
        )
        << " MB\n"
        << '\n'
        << " RX Packets/sec  : "
        << stats.rxPacketsPerSecond
        << '\n'
        << " TX Packets/sec  : "
        << stats.txPacketsPerSecond
        << '\n'
        << " RX Rate         : "
        << bytesToKB(
            stats.rxBytesPerSecond
        )
        << " KB/s\n"
        << " TX Rate         : "
        << bytesToKB(
            stats.txBytesPerSecond
        )
        << " KB/s\n"
        << '\n'
        << " RX Errors       : "
        << stats.rxErrors
        << '\n'
        << " TX Errors       : "
        << stats.txErrors
        << '\n'
        << " RX Dropped      : "
        << stats.rxDropped
        << '\n'
        << " TX Dropped      : "
        << stats.txDropped
        << '\n'
        << "============================================================\n";
}


bool NetworkMonitor::monitor(
    const std::string& interfaceName,
    int intervalSeconds
) const
{
    /*
     * --------------------------------------------------------
     * Validation
     * --------------------------------------------------------
     */

    if (interfaceName.empty())
    {
        std::cout
            << "\n[!] Network interface is empty.\n";

        return false;
    }

    if (
        intervalSeconds <= 0 ||
        intervalSeconds > 3600
    )
    {
        std::cout
            << "\n[!] Monitoring interval must be between "
            << "1 and 3600 seconds.\n";

        return false;
    }

    if (
        !slipnet::platform::networkStatusAvailable()
    )
    {
        std::cout
            << "\n[!] Network monitoring backend is unavailable.\n";

        return false;
    }

    /*
     * --------------------------------------------------------
     * Clear any previous Ctrl+C request
     * --------------------------------------------------------
     */

    SignalHandler::clearStop();

    /*
     * --------------------------------------------------------
     * Initial snapshot
     * --------------------------------------------------------
     */

    const auto initial =
        readStats(interfaceName);

    if (
        initial.interfaceName.empty()
    )
    {
        std::cout
            << "\n[!] Unable to access network interface:\n"
            << "    "
            << interfaceName
            << '\n';

        return false;
    }

    /*
     * --------------------------------------------------------
     * Header
     * --------------------------------------------------------
     */

    displayHeader(
        interfaceName,
        intervalSeconds
    );

    std::cout
        << "\n[*] Network monitoring started.\n"
        << "[*] Press Ctrl+C to stop.\n\n";

    /*
     * --------------------------------------------------------
     * Continuous monitoring
     * --------------------------------------------------------
     */

    NetworkStats previous =
        initial;

    const auto monitorStart =
        std::chrono::steady_clock::now();

    auto previousSampleTime =
        monitorStart;

    while (
        !SignalHandler::isStopRequested()
    )
    {
        /*
         * Sleep in small increments so Ctrl+C
         * can terminate monitoring promptly.
         */
        for (
            int second = 0;
            second < intervalSeconds;
            ++second
        )
        {
            if (
                SignalHandler::isStopRequested()
            )
            {
                break;
            }

            std::this_thread::sleep_for(
                std::chrono::seconds(1)
            );
        }

        if (
            SignalHandler::isStopRequested()
        )
        {
            break;
        }

        const auto sampleTime =
            std::chrono::steady_clock::now();

        const auto current =
            readStats(interfaceName);

        const double elapsedSeconds =
            std::chrono::duration<double>(
                sampleTime -
                previousSampleTime
            ).count();

        displaySample(
            previous,
            current,
            elapsedSeconds
        );

        previous =
            current;

        previousSampleTime =
            sampleTime;
    }

    /*
     * --------------------------------------------------------
     * Final snapshot
     * --------------------------------------------------------
     */

    const auto final =
        readStats(interfaceName);

    const auto monitorEnd =
        std::chrono::steady_clock::now();

    const double totalElapsed =
        std::chrono::duration<double>(
            monitorEnd -
            monitorStart
        ).count();

    /*
     * --------------------------------------------------------
     * Final report
     * --------------------------------------------------------
     */

    displaySummary(
        initial,
        final,
        totalElapsed
    );

    std::cout
        << "\n[+] Network monitoring stopped.\n";

    /*
     * Clear the stop flag so the CLI can continue
     * accepting commands after Ctrl+C.
     */
    SignalHandler::clearStop();

    return true;
}

} // namespace slipnet::monitoring