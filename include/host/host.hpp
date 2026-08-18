#pragma once

#include <string>

struct Host
{
    std::string ip;

    bool reachable;

    double latencyMs;
};