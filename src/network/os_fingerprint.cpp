#include "network/os_fingerprint.hpp"
#include "platform/os_fingerprint.hpp"

OSFingerprint
OSFingerprinter::fingerprint(
    const std::string& target
) const
{
    OSFingerprint result;

    result.target = target;

    /*
     * --------------------------------------------------------
     * Platform probe
     * --------------------------------------------------------
     *
     * The actual ICMP/ping implementation is platform-specific.
     *
     * Linux  -> Linux platform implementation
     * Windows -> Windows platform implementation
     *
     * The resulting TTL is interpreted here.
     */

    const auto probe =
        slipnet::platform::fingerprintHost(
            target
        );

    if (!probe.reachable)
    {
        return result;
    }

    const int ttl =
        probe.ttl;

    if (ttl <= 0)
    {
        return result;
    }

    result.ttl =
        ttl;

    result.detected =
        true;


    /*
     * --------------------------------------------------------
     * TTL heuristic
     * --------------------------------------------------------
     *
     * Typical initial TTL values:
     *
     *   Linux / Unix-like       64
     *   Windows                128
     *   Network appliances     255
     *
     * This is a heuristic and does NOT prove the OS.
     */

    if (ttl <= 64)
    {
        result.operatingSystem =
            "Linux / Unix-like";

        result.confidence =
            ttl == 64
                ? "HIGH"
                : "MEDIUM";
    }
    else if (ttl <= 128)
    {
        result.operatingSystem =
            "Windows";

        result.confidence =
            ttl == 128
                ? "HIGH"
                : "MEDIUM";
    }
    else if (ttl <= 255)
    {
        result.operatingSystem =
            "Network appliance / embedded";

        result.confidence =
            ttl == 255
                ? "HIGH"
                : "LOW";
    }
    else
    {
        result.operatingSystem =
            "Unknown";

        result.confidence =
            "LOW";
    }

    return result;
}