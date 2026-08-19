#pragma once

#include <cstdint>

struct NetworkStats
{
    uint64_t receivedBytes = 0;
    uint64_t transmittedBytes = 0;

    uint64_t receivedPackets = 0;
    uint64_t transmittedPackets = 0;
};