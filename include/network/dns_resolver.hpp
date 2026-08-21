#pragma once

#include <string>
#include <vector>

struct DNSResult
{
    bool success = false;

    std::string input;
    std::string canonicalName;

    std::vector<std::string> addresses;

    std::string reverseName;
};

class DNSResolver
{
public:

    DNSResult resolve(
        const std::string& input
    ) const;

private:

    bool isIPAddress(
        const std::string& value
    ) const;
};