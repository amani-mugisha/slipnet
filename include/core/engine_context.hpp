#pragma once

#include "core/network_state.hpp"

#include <string>


class EngineContext
{
public:

    NetworkState network;

    bool running = true;

    std::string version = "0.1.0";
};