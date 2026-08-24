#pragma once

#include <string>

namespace slipnet::platform {

struct PingResult
{
    bool reachable{false};
    double latencyMs{0.0};
};

PingResult pingHost(
    const std::string& ip
);

} // namespace slipnet::platform