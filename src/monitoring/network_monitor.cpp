#include "monitoring/network_monitor.hpp"

#include "cli/signal_handler.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>


namespace
{

constexpr const char* SYS_NET_PATH = "/sys/class/net";

constexpr auto SAMPLE_INTERVAL =
    std::chrono::milliseconds(1000);


/*
 * ============================================================
 * READ LINUX NETWORK COUNTER
 * ============================================================
 */

uint64_t readCounter(
    const std::string& path
)
{
    std::ifstream file(path);

    if (!file.is_open())
    {
        return 0;
    }

    uint64_t value = 0;

    file >> value;

    return value;
}


/*
 * ============================================================
 * INTERFACE PATH
 * ============================================================
 */

std::string interfacePath(
    const std::string& interfaceName
)
{
    return std::string(SYS_NET_PATH)
        + "/"
        + interfaceName;
}


/*
 * ============================================================
 * INTERFACE EXISTS
 * ============================================================
 */

bool interfaceExists(
    const std::string& interfaceName
)
{
    if (interfaceName.empty())
    {
        return false;
    }

    return std::filesystem::exists(
        interfacePath(interfaceName)
    );
}


/*
 * ============================================================
 * INTERFACE STATE
 * ============================================================
 */

std::string readInterfaceState(
    const std::string& interfaceName
)
{
    std::ifstream file(
        interfacePath(interfaceName)
        + "/operstate"
    );

    if (!file.is_open())
    {
        return "unknown";
    }

    std::string state;

    file >> state;

    return state;
}


/*
 * ============================================================
 * SAFE COUNTER DIFFERENCE
 * ============================================================
 *
 * Protects against counter resets.
 */

uint64_t counterDelta(
    uint64_t current,
    uint64_t previous
)
{
    if (current >= previous)
    {
        return current - previous;
    }

    return 0;
}


/*
 * ============================================================
 * FORMAT BYTES
 * ============================================================
 */

std::string formatBytes(
    uint64_t bytes
)
{
    std::ostringstream output;

    if (bytes < 1024ULL)
    {
        output
            << bytes
            << " B";

        return output.str();
    }

    if (bytes < 1024ULL * 1024ULL)
    {
        output
            << std::fixed
            << std::setprecision(1)
            << (
                static_cast<double>(bytes)
                / 1024.0
            )
            << " KB";

        return output.str();
    }

    if (bytes < 1024ULL * 1024ULL * 1024ULL)
    {
        output
            << std::fixed
            << std::setprecision(1)
            << (
                static_cast<double>(bytes)
                /
                (1024.0 * 1024.0)
            )
            << " MB";

        return output.str();
    }

    output
        << std::fixed
        << std::setprecision(2)
        << (
            static_cast<double>(bytes)
            /
            (
                1024.0
                * 1024.0
                * 1024.0
            )
        )
        << " GB";

    return output.str();
}


/*
 * ============================================================
 * FORMAT ELAPSED TIME
 * ============================================================
 */

std::string formatElapsed(
    uint64_t seconds
)
{
    const uint64_t minutes =
        seconds / 60;

    const uint64_t remainingSeconds =
        seconds % 60;

    std::ostringstream output;

    output
        << std::setfill('0')
        << std::setw(2)
        << minutes
        << ":"
        << std::setw(2)
        << remainingSeconds;

    return output.str();
}

}


/*
 * ============================================================
 * READ STATISTICS
 * ============================================================
 */

NetworkStats NetworkMonitor::read(
    const std::string& interfaceName
) const
{
    const std::string base =
        interfacePath(interfaceName)
        + "/statistics/";

    NetworkStats stats;

    stats.receivedBytes =
        readCounter(
            base + "rx_bytes"
        );

    stats.transmittedBytes =
        readCounter(
            base + "tx_bytes"
        );

    stats.receivedPackets =
        readCounter(
            base + "rx_packets"
        );

    stats.transmittedPackets =
        readCounter(
            base + "tx_packets"
        );

    return stats;
}


/*
 * ============================================================
 * DETECT ACTIVE INTERFACE
 * ============================================================
 *
 * Priority:
 *
 * 1. UP interface with traffic
 * 2. UP interface
 * 3. Any non-loopback interface
 *
 * This prevents SlipNet from accidentally selecting
 * loopback when a real interface is available.
 */

std::string NetworkMonitor::detectActiveInterface() const
{
    namespace fs = std::filesystem;

    try
    {
        if (!fs::exists(SYS_NET_PATH))
        {
            return "";
        }

        std::string bestInterface;

        /*
         * ----------------------------------------------------
         * First pass:
         * UP + actual traffic
         * ----------------------------------------------------
         */

        for (
            const auto& entry :
            fs::directory_iterator(SYS_NET_PATH)
        )
        {
            const std::string name =
                entry.path().filename().string();

            if (
                name == "lo" ||
                name == "loopback0"
            )
            {
                continue;
            }

            if (
                readInterfaceState(name)
                != "up"
            )
            {
                continue;
            }

            const uint64_t rx =
                readCounter(
                    entry.path().string()
                    + "/statistics/rx_bytes"
                );

            const uint64_t tx =
                readCounter(
                    entry.path().string()
                    + "/statistics/tx_bytes"
                );

            if (
                rx > 0 ||
                tx > 0
            )
            {
                return name;
            }
        }


        /*
         * ----------------------------------------------------
         * Second pass:
         * Any UP interface.
         * ----------------------------------------------------
         */

        for (
            const auto& entry :
            fs::directory_iterator(SYS_NET_PATH)
        )
        {
            const std::string name =
                entry.path().filename().string();

            if (
                name == "lo" ||
                name == "loopback0"
            )
            {
                continue;
            }

            if (
                readInterfaceState(name)
                == "up"
            )
            {
                return name;
            }
        }


        /*
         * ----------------------------------------------------
         * Final fallback:
         * Any non-loopback interface.
         * ----------------------------------------------------
         */

        for (
            const auto& entry :
            fs::directory_iterator(SYS_NET_PATH)
        )
        {
            const std::string name =
                entry.path().filename().string();

            if (
                name == "lo" ||
                name == "loopback0"
            )
            {
                continue;
            }

            bestInterface = name;

            break;
        }

        return bestInterface;
    }
    catch (...)
    {
        return "";
    }
}


/*
 * ============================================================
 * FORMAT RATE
 * ============================================================
 */

std::string NetworkMonitor::formatRate(
    double bytesPerSecond
) const
{
    if (bytesPerSecond < 0.0)
    {
        bytesPerSecond = 0.0;
    }

    std::ostringstream output;

    /*
     * Zero is displayed cleanly.
     */

    if (bytesPerSecond < 1.0)
    {
        output
            << "0 B/s";

        return output.str();
    }


    /*
     * Bytes per second.
     */

    if (bytesPerSecond < 1024.0)
    {
        output
            << std::fixed
            << std::setprecision(
                bytesPerSecond < 10.0
                    ? 1
                    : 0
            )
            << bytesPerSecond
            << " B/s";

        return output.str();
    }


    /*
     * Kilobytes per second.
     */

    if (bytesPerSecond < 1024.0 * 1024.0)
    {
        output
            << std::fixed
            << std::setprecision(1)
            << (
                bytesPerSecond
                / 1024.0
            )
            << " KB/s";

        return output.str();
    }


    /*
     * Megabytes per second.
     */

    if (bytesPerSecond < 1024.0 * 1024.0 * 1024.0)
    {
        output
            << std::fixed
            << std::setprecision(2)
            << (
                bytesPerSecond
                /
                (1024.0 * 1024.0)
            )
            << " MB/s";

        return output.str();
    }


    /*
     * Gigabytes per second.
     */

    output
        << std::fixed
        << std::setprecision(2)
        << (
            bytesPerSecond
            /
            (
                1024.0
                * 1024.0
                * 1024.0
            )
        )
        << " GB/s";

    return output.str();
}


/*
 * ============================================================
 * PRINT HEADER
 * ============================================================
 */

void NetworkMonitor::printHeader(
    const std::string& interfaceName,
    const std::string& state,
    int seconds
) const
{
    std::cout
        << "\n"
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: NETWORK MONITOR                                   │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n"
        << "\n";

    std::cout
        << " Interface   "
        << interfaceName
        << "\n";

    std::cout
        << " State       "
        << (
            state == "up"
                ? "● UP"
                : "● " + state
        )
        << "\n";

    if (seconds > 0)
    {
        std::cout
            << " Duration    "
            << seconds
            << " second"
            << (
                seconds == 1
                    ? ""
                    : "s"
            )
            << "\n";
    }
    else
    {
        std::cout
            << " Duration    Continuous\n";
    }

    std::cout
        << " Sampling    1.00 second\n"
        << "\n"
        << " Press Ctrl+C to stop monitoring.\n"
        << "\n";
}


/*
 * ============================================================
 * PRINT TABLE HEADER
 * ============================================================
 */

void NetworkMonitor::printTableHeader() const
{
    std::cout
        << "┌────────┬────────────┬────────────┬──────────┬──────────┐\n"
        << "│ TIME   │ RX RATE    │ TX RATE    │ RX PKT/s │ TX PKT/s │\n"
        << "├────────┼────────────┼────────────┼──────────┼──────────┤\n";
}


/*
 * ============================================================
 * PRINT TABLE ROW
 * ============================================================
 */

void NetworkMonitor::printTableRow(
    uint64_t elapsed,
    double rxRate,
    double txRate,
    uint64_t rxPackets,
    uint64_t txPackets
) const
{
    std::cout
        << "│ "
        << std::left
        << std::setw(6)
        << formatElapsed(elapsed)
        << " │ "
        << std::setw(10)
        << formatRate(rxRate)
        << " │ "
        << std::setw(10)
        << formatRate(txRate)
        << " │ "
        << std::right
        << std::setw(8)
        << rxPackets
        << " │ "
        << std::setw(8)
        << txPackets
        << " │\n";
}


/*
 * ============================================================
 * PRINT SUMMARY
 * ============================================================
 */

void NetworkMonitor::printSummary(
    const std::string& interfaceName,
    uint64_t totalRxBytes,
    uint64_t totalTxBytes,
    uint64_t totalRxPackets,
    uint64_t totalTxPackets,
    double rxAverage,
    double txAverage,
    double rxPeak,
    double txPeak,
    bool interrupted
) const
{
    std::cout
        << "└────────┴────────────┴────────────┴──────────┴──────────┘\n"
        << "\n";


    /*
     * --------------------------------------------------------
     * TRAFFIC
     * --------------------------------------------------------
     */

    std::cout
        << " TRAFFIC\n"
        << " ────────────────────────────────────────────────────────────\n";

    std::cout
        << " RX                 "
        << formatBytes(totalRxBytes)
        << "        "
        << totalRxPackets
        << " packets\n";

    std::cout
        << " TX                 "
        << formatBytes(totalTxBytes)
        << "        "
        << totalTxPackets
        << " packets\n";


    /*
     * --------------------------------------------------------
     * PERFORMANCE
     * --------------------------------------------------------
     */

    std::cout
        << "\n"
        << " PERFORMANCE\n"
        << " ────────────────────────────────────────────────────────────\n";

    std::cout
        << " RX AVG             "
        << formatRate(rxAverage)
        << "\n";

    std::cout
        << " TX AVG             "
        << formatRate(txAverage)
        << "\n";

    std::cout
        << " RX PEAK            "
        << formatRate(rxPeak)
        << "\n";

    std::cout
        << " TX PEAK            "
        << formatRate(txPeak)
        << "\n";


    /*
     * --------------------------------------------------------
     * ACTIVITY
     * --------------------------------------------------------
     */

    std::cout
        << "\n"
        << " ACTIVITY\n"
        << " ────────────────────────────────────────────────────────────\n";

    std::cout
        << " RX                 "
        << (
            totalRxBytes > 0
                ? "ACTIVE"
                : "IDLE"
        )
        << "\n";

    std::cout
        << " TX                 "
        << (
            totalTxBytes > 0
                ? "ACTIVE"
                : "IDLE"
        )
        << "\n";


    /*
     * --------------------------------------------------------
     * STATUS
     * --------------------------------------------------------
     */

    const std::string state =
        readInterfaceState(
            interfaceName
        );

    std::cout
        << "\n"
        << " STATUS\n"
        << " ────────────────────────────────────────────────────────────\n";

    std::cout
        << " Link State         "
        << (
            state == "up"
                ? "● UP"
                : "● " + state
        )
        << "\n";

    std::cout
        << " Monitoring         "
        << (
            interrupted
                ? "INTERRUPTED"
                : "COMPLETED"
        )
        << "\n";
}


/*
 * ============================================================
 * MONITOR
 * ============================================================
 */

void NetworkMonitor::monitor(
    const std::string& interfaceName,
    int seconds
) const
{
    /*
     * --------------------------------------------------------
     * Determine interface.
     *
     * Empty interface means automatic detection.
     * --------------------------------------------------------
     */

    std::string selectedInterface =
        interfaceName;

    if (selectedInterface.empty())
    {
        std::cout
            << "\n"
            << "[*] Detecting active network interface...\n";

        selectedInterface =
            detectActiveInterface();

        if (selectedInterface.empty())
        {
            std::cout
                << "[!] No usable network interface found.\n";

            return;
        }

        std::cout
            << "[+] Active interface: "
            << selectedInterface
            << "\n";
    }


    /*
     * --------------------------------------------------------
     * Validate interface.
     * --------------------------------------------------------
     */

    if (
        !interfaceExists(
            selectedInterface
        )
    )
    {
        std::cout
            << "\n"
            << "[!] Interface '"
            << selectedInterface
            << "' does not exist.\n"
            << "[*] Use ip|:seek to discover interfaces.\n";

        return;
    }


    /*
     * --------------------------------------------------------
     * Validate duration.
     * --------------------------------------------------------
     */

    if (seconds < 0)
    {
        std::cout
            << "\n"
            << "[!] Monitoring duration cannot be negative.\n";

        return;
    }


    /*
     * --------------------------------------------------------
     * Validate interface state.
     * --------------------------------------------------------
     */

    const std::string initialState =
        readInterfaceState(
            selectedInterface
        );

    if (initialState != "up")
    {
        std::cout
            << "\n"
            << "[!] Interface '"
            << selectedInterface
            << "' is "
            << initialState
            << ".\n"
            << "[*] Choose an interface whose state is UP.\n";

        return;
    }


    /*
     * --------------------------------------------------------
     * Reset Ctrl+C state.
     * --------------------------------------------------------
     */

    SignalHandler::clearStop();


    /*
     * --------------------------------------------------------
     * Initial statistics.
     * --------------------------------------------------------
     */

    NetworkStats previous =
        read(selectedInterface);


    /*
     * --------------------------------------------------------
     * Totals.
     * --------------------------------------------------------
     */

    uint64_t totalRxBytes = 0;
    uint64_t totalTxBytes = 0;

    uint64_t totalRxPackets = 0;
    uint64_t totalTxPackets = 0;


    /*
     * --------------------------------------------------------
     * Performance metrics.
     * --------------------------------------------------------
     */

    double rxRateSum = 0.0;
    double txRateSum = 0.0;

    double rxPeak = 0.0;
    double txPeak = 0.0;


    uint64_t samples = 0;
    uint64_t elapsedSeconds = 0;


    /*
     * --------------------------------------------------------
     * High-resolution timing.
     * --------------------------------------------------------
     */

    const auto monitorStart =
        std::chrono::steady_clock::now();

    auto previousSample =
        monitorStart;


    /*
     * --------------------------------------------------------
     * Header.
     * --------------------------------------------------------
     */

    printHeader(
        selectedInterface,
        initialState,
        seconds
    );

    printTableHeader();


    /*
     * --------------------------------------------------------
     * Monitoring loop.
     * --------------------------------------------------------
     */

    while (true)
    {
        /*
         * Ctrl+C.
         */

        if (
            SignalHandler::isStopRequested()
        )
        {
            break;
        }


        /*
         * Timed duration.
         */

        if (seconds > 0)
        {
            const auto now =
                std::chrono::steady_clock::now();

            const auto elapsed =
                std::chrono::duration_cast<
                    std::chrono::seconds
                >(
                    now - monitorStart
                ).count();

            if (
                elapsed >= seconds
            )
            {
                break;
            }
        }


        /*
         * Sleep until the next sample.
         */

        std::this_thread::sleep_for(
            SAMPLE_INTERVAL
        );


        /*
         * Ctrl+C can arrive during sleep.
         */

        if (
            SignalHandler::isStopRequested()
        )
        {
            break;
        }


        /*
         * Interface may disappear.
         */

        if (
            !interfaceExists(
                selectedInterface
            )
        )
        {
            std::cout
                << "\n"
                << "[!] Interface '"
                << selectedInterface
                << "' disappeared.\n";

            break;
        }


        /*
         * Read current statistics.
         */

        const NetworkStats current =
            read(selectedInterface);


        /*
         * Actual sample duration.
         */

        const auto now =
            std::chrono::steady_clock::now();

        const std::chrono::duration<double>
            sampleDuration =
                now - previousSample;

        previousSample = now;


        double intervalSeconds =
            sampleDuration.count();

        if (intervalSeconds <= 0.0)
        {
            intervalSeconds = 1.0;
        }


        /*
         * Counter deltas.
         */

        const uint64_t rxBytes =
            counterDelta(
                current.receivedBytes,
                previous.receivedBytes
            );

        const uint64_t txBytes =
            counterDelta(
                current.transmittedBytes,
                previous.transmittedBytes
            );

        const uint64_t rxPackets =
            counterDelta(
                current.receivedPackets,
                previous.receivedPackets
            );

        const uint64_t txPackets =
            counterDelta(
                current.transmittedPackets,
                previous.transmittedPackets
            );


        /*
         * Actual rates.
         */

        const double rxRate =
            static_cast<double>(rxBytes)
            /
            intervalSeconds;

        const double txRate =
            static_cast<double>(txBytes)
            /
            intervalSeconds;

        const double rxPacketRate =
            static_cast<double>(rxPackets)
            /
            intervalSeconds;

        const double txPacketRate =
            static_cast<double>(txPackets)
            /
            intervalSeconds;


        /*
         * Convert elapsed time to display seconds.
         */

        ++samples;

        const auto totalElapsed =
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                now - monitorStart
            ).count();

        elapsedSeconds =
            static_cast<uint64_t>(
                std::max<int64_t>(
                    1,
                    totalElapsed
                )
            );


        /*
         * Totals.
         */

        totalRxBytes += rxBytes;
        totalTxBytes += txBytes;

        totalRxPackets += rxPackets;
        totalTxPackets += txPackets;


        /*
         * Average accumulation.
         */

        rxRateSum += rxRate;
        txRateSum += txRate;


        /*
         * Peak.
         */

        rxPeak =
            std::max(
                rxPeak,
                rxRate
            );

        txPeak =
            std::max(
                txPeak,
                txRate
            );


        /*
         * Display.
         *
         * The existing table stores packet counts,
         * so round the packet rate to an integer for display.
         */

        printTableRow(
            elapsedSeconds,
            rxRate,
            txRate,
            static_cast<uint64_t>(
                rxPacketRate + 0.5
            ),
            static_cast<uint64_t>(
                txPacketRate + 0.5
            )
        );


        /*
         * Current becomes previous.
         */

        previous = current;


        /*
         * Timed session completion.
         */

        if (seconds > 0)
        {
            const auto currentElapsed =
                std::chrono::duration_cast<
                    std::chrono::seconds
                >(
                    now - monitorStart
                ).count();

            if (
                currentElapsed >= seconds
            )
            {
                break;
            }
        }
    }


    /*
     * --------------------------------------------------------
     * Calculate averages.
     * --------------------------------------------------------
     */

    double rxAverage = 0.0;
    double txAverage = 0.0;

    if (samples > 0)
    {
        rxAverage =
            rxRateSum
            /
            static_cast<double>(
                samples
            );

        txAverage =
            txRateSum
            /
            static_cast<double>(
                samples
            );
    }


    /*
     * --------------------------------------------------------
     * Stop reason.
     * --------------------------------------------------------
     */

    const bool interrupted =
        SignalHandler::isStopRequested();


    /*
     * --------------------------------------------------------
     * Summary.
     * --------------------------------------------------------
     */

    printSummary(
        selectedInterface,
        totalRxBytes,
        totalTxBytes,
        totalRxPackets,
        totalTxPackets,
        rxAverage,
        txAverage,
        rxPeak,
        txPeak,
        interrupted
    );


    /*
     * --------------------------------------------------------
     * Final message.
     * --------------------------------------------------------
     */

    if (interrupted)
    {
        std::cout
            << "\n"
            << "[!] Monitoring interrupted by user.\n";
    }
    else
    {
        std::cout
            << "\n"
            << "[+] Monitoring session completed.\n";
    }


    /*
     * --------------------------------------------------------
     * Reset signal state.
     * --------------------------------------------------------
     */

    SignalHandler::clearStop();
}