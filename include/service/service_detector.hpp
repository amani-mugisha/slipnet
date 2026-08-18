#pragma once

#include <string>

#include <vector>

#include "service/service.hpp"


class ServiceDetector
{
public:

    Service detect(
        const std::string& host,
        int port
    ) const;


    std::vector<Service> detect(
        const std::string& host,
        const std::vector<int>& ports
    ) const;


private:

    std::string probe(
        const std::string& host,
        int port
    ) const;


    Service identify(
        int port,
        const std::string& response
    ) const;
};