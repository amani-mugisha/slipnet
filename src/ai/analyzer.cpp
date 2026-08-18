#include "ai/analyzer.hpp"

#include <iostream>

double Analyzer::calculateRisk(
    const std::vector<Feature>& features
) const
{
    double score = 0;

    for (
        const auto& feature :
        features
    )
    {
        score += feature.value;
    }

    if (score > 100)
    {
        score = 100;
    }

    return score;
}

void Analyzer::analyze(
    const std::vector<Feature>& features
) const
{
    double risk =
        calculateRisk(features);

    std::cout
        << "\nAI SECURITY ANALYSIS\n"
        << "===================\n";

    std::cout
        << "Risk score: "
        << risk
        << "/100\n";

    if (risk < 30)
    {
        std::cout
            << "Risk level: LOW\n";
    }
    else if (risk < 70)
    {
        std::cout
            << "Risk level: MEDIUM\n";
    }
    else
    {
        std::cout
            << "Risk level: HIGH\n";
    }
}