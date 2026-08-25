#pragma once

#include <string>

namespace slipnet::platform
{

enum class FirewallProbeState
{
    OPEN,
    CLOSED,
    FILTERED,
    UNKNOWN
};

struct FirewallProbeResult
{
    FirewallProbeState state =
        FirewallProbeState::UNKNOWN;

    int port = 0;

    int latencyMs = -1;

    std::string evidence;
};

FirewallProbeResult probeTCP(
    const std::string& host,
    int port,
    int timeoutMs = 1500
);

} // namespace slipnet::platform