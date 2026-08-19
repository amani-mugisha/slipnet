#pragma once

#include <cstdint>
#include <string>

#include "monitoring/network_stats.hpp"


class NetworkMonitor
{
public:

    /*
     * Read current Linux interface statistics.
     */
    NetworkStats read(
        const std::string& interfaceName
    ) const;


    /*
     * Start live network monitoring.
     *
     * seconds == 0
     *     Continuous monitoring.
     *
     * seconds > 0
     *     Monitor for the specified duration.
     */
    void monitor(
        const std::string& interfaceName,
        int seconds
    ) const;


    /*
     * Automatically detect the best active
     * network interface.
     */
    std::string detectActiveInterface() const;


private:

    /*
     * Format a bandwidth value.
     */
    std::string formatRate(
        double bytesPerSecond
    ) const;


    /*
     * Display monitor header.
     */
    void printHeader(
        const std::string& interfaceName,
        const std::string& state,
        int seconds
    ) const;


    /*
     * Display table header.
     */
    void printTableHeader() const;


    /*
     * Display one monitoring sample.
     */
    void printTableRow(
        uint64_t elapsed,
        double rxRate,
        double txRate,
        uint64_t rxPackets,
        uint64_t txPackets
    ) const;


    /*
     * Display final monitoring summary.
     */
    void printSummary(
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
    ) const;
};