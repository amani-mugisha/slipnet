#include "security/firewall_probe.hpp"

#include <sstream>

FirewallState
FirewallProbe::classify(
    const PortInfo& port
)
{
    if (port.open)
    {
        return FirewallState::OPEN;
    }

    /*
     * The current PortInfo structure only records
     * whether a port was open.
     *
     * Therefore a non-open port cannot safely be
     * classified as FILTERED.
     */
    return FirewallState::CLOSED;
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
    const std::vector<PortInfo>& ports
) const
{
    FirewallReport report;

    report.host = host;
    report.observed =
        static_cast<int>(
            ports.size()
        );

    for (const auto& port : ports)
    {
        FirewallObservation observation;

        observation.host = host;
        observation.port = port.port;

        observation.state =
            classify(port);

        switch (observation.state)
        {
            case FirewallState::OPEN:
                ++report.open;

                observation.evidence =
                    "TCP service responded as open.";
                break;

            case FirewallState::CLOSED:
                ++report.closed;

                observation.evidence =
                    "Port was scanned but was not observed "
                    "as open. This alone does not prove filtering.";
                break;

            default:
                ++report.unknown;

                observation.evidence =
                    "Insufficient evidence for classification.";
                break;
        }

        report.observations.push_back(
            observation
        );
    }

    /*
     * With the current scanner data we cannot honestly
     * identify filtered ports.
     */
    report.hasEvidenceOfFiltering = false;

    if (report.observed == 0)
    {
        report.conclusion =
            "No port observations are available.";
    }
    else if (
        report.open == report.observed
    )
    {
        report.conclusion =
            "All observed ports were reachable as open. "
            "No firewall filtering can be inferred from "
            "the current dataset.";
    }
    else if (
        report.open > 0 &&
        report.closed > 0
    )
    {
        report.conclusion =
            "Both open and non-open ports were observed. "
            "The current scanner cannot distinguish closed "
            "ports from firewall filtering.";
    }
    else
    {
        report.conclusion =
            "No scanned ports were observed as open. "
            "This does not establish that a firewall is present.";
    }

    return report;
}