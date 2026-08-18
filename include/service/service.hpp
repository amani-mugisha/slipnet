#pragma once

#include <string>


struct Service
{
    int port;

    std::string protocol;

    std::string name;

    std::string version;

    std::string banner;

    bool detected;
};