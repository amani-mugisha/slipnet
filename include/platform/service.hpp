#pragma once

#include <string>

namespace slipnet::platform {

struct ServiceProbeResult
{
    bool connected{false};
    std::string response;
    double latencyMs{0.0};
};

ServiceProbeResult probeService(
    const std::string& host,
    int port,
    const std::string& request,
    int timeoutMs
);

} // namespace slipnet::platform