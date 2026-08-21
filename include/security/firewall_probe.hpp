#pragma once

#include "core/network_state.hpp"

#include <string>
#include <vector>

enum class FirewallState
{
    OPEN,
    CLOSED,
    FILTERED,
    UNKNOWN
};

struct FirewallObservation
{
    std::string host;

    int port = 0;

    FirewallState state =
        FirewallState::UNKNOWN;

    std::string evidence;
};

struct FirewallReport
{
    std::string host;

    int observed = 0;
    int open = 0;
    int closed = 0;
    int unknown = 0;

    std::vector<FirewallObservation>
        observations;

    bool hasEvidenceOfFiltering = false;

    std::string conclusion;
};

class FirewallProbe
{
public:

    FirewallReport analyze(
        const std::string& host,
        const std::vector<PortInfo>& ports
    ) const;

private:

    static FirewallState classify(
        const PortInfo& port
    );

    static std::string stateName(
        FirewallState state
    );
};