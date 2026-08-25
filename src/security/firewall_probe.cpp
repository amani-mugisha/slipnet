#include "security/firewall_probe.hpp"

#include "platform/firewall.hpp"

#include <algorithm>

FirewallState
FirewallProbe::convertState(
    int state
)
{
    using PlatformState =
        slipnet::platform::FirewallProbeState;

    switch (
        static_cast<PlatformState>(state)
    )
    {
        case PlatformState::OPEN:
            return FirewallState::OPEN;

        case PlatformState::CLOSED:
            return FirewallState::CLOSED;

        case PlatformState::FILTERED:
            return FirewallState::FILTERED;

        default:
            return FirewallState::UNKNOWN;
    }
}

std::string
FirewallProbe::stateName(
    FirewallState state
)
{
    switch (state)
    {
        case FirewallState::OPEN:
            return "OPEN";

        case FirewallState::CLOSED:
            return "CLOSED";

        case FirewallState::FILTERED:
            return "FILTERED";

        default:
            return "UNKNOWN";
    }
}

FirewallReport
FirewallProbe::analyze(
    const std::string& host,
    const std::vector<int>& ports
) const
{
    FirewallReport report;

    report.host = host;

    for (const int port : ports)
    {
        if (port < 1 || port > 65535)
        {
            continue;
        }

        const auto result =
            slipnet::platform::probeTCP(
                host,
                port,
                1500
            );

        FirewallObservation observation;

        observation.host = host;
        observation.port = port;
        observation.latencyMs =
            result.latencyMs;

        observation.state =
            convertState(
                static_cast<int>(
                    result.state
                )
            );

        observation.evidence =
            result.evidence;

        ++report.observed;

        switch (observation.state)
        {
            case FirewallState::OPEN:
                ++report.open;
                break;

            case FirewallState::CLOSED:
                ++report.closed;
                break;

            case FirewallState::FILTERED:
                ++report.filtered;
                report.hasEvidenceOfFiltering = true;
                break;

            case FirewallState::UNKNOWN:
                ++report.unknown;
                break;
        }

        report.observations.push_back(
            observation
        );
    }

    if (report.observed == 0)
    {
        report.conclusion =
            "No valid TCP ports were available for probing.";
    }
    else if (report.filtered > 0)
    {
        report.conclusion =
            "Filtering behavior was observed on one or more "
            "TCP ports. This indicates packet filtering or "
            "silent traffic dropping, but does not identify "
            "a specific firewall product.";
    }
    else if (
        report.open > 0 &&
        report.closed > 0
    )
    {
        report.conclusion =
            "Both reachable and explicitly refused TCP ports "
            "were observed. No filtering behavior was directly "
            "identified in the tested ports.";
    }
    else if (report.open > 0)
    {
        report.conclusion =
            "The tested ports responded as reachable. "
            "No filtering behavior was directly observed.";
    }
    else if (report.closed == report.observed)
    {
        report.conclusion =
            "All tested ports explicitly refused the TCP "
            "connection. No filtering behavior was directly "
            "observed.";
    }
    else
    {
        report.conclusion =
            "The available observations were insufficient "
            "to determine firewall behavior.";
    }

    return report;
}