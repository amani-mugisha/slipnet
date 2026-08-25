#pragma once

#include <string>


struct Alert
{

    std::string type;

    std::string description;

    int severity = 0;
};