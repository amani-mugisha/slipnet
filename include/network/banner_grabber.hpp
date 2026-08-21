#pragma once

#include <string>

struct BannerResult
{
    bool connected = false;

    std::string host;
    int port = 0;

    std::string protocol;
    std::string banner;
};

class BannerGrabber
{
public:

    BannerResult grab(
        const std::string& host,
        int port
    ) const;

private:

    std::string clean(
        const std::string& value
    ) const;
};