#pragma once

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

    int latencyMs = -1;

    std::string evidence;
};

struct FirewallReport
{
    std::string host;

    int observed = 0;
    int open = 0;
    int closed = 0;
    int filtered = 0;
    int unknown = 0;

    bool hasEvidenceOfFiltering = false;

    std::vector<FirewallObservation>
        observations;

    std::string conclusion;
};

class FirewallProbe
{
public:

    FirewallReport analyze(
        const std::string& host,
        const std::vector<int>& ports
    ) const;

private:

    static FirewallState convertState(
        int state
    );

    static std::string stateName(
        FirewallState state
    );
};