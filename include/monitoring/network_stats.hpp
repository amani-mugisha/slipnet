#pragma once

#include <cstdint>

struct NetworkStats
{
    uint64_t receivedBytes;

    uint64_t transmittedBytes;

    uint64_t receivedPackets;

    uint64_t transmittedPackets;
};