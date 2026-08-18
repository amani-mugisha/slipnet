#pragma once

#include <vector>

#include "ai/feature.hpp"

class Analyzer
{
public:

    double calculateRisk(
        const std::vector<Feature>& features
    ) const;

    void analyze(
        const std::vector<Feature>& features
    ) const;
};