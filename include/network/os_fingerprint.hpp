#pragma once

#include <string>

struct OSFingerprint
{
    bool detected = false;

    std::string target;
    std::string operatingSystem;
    std::string confidence;
    int ttl = 0;
};

class OSFingerprinter
{
public:

    OSFingerprint fingerprint(
        const std::string& target
    ) const;
};