#pragma once

#include <string>

struct Packet
{
    std::string source;

    std::string destination;

    std::string protocol;

    int length;
};