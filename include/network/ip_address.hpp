#pragma once
#include<string>

class IPAddress {
    public:
        explicit IPAddress(const std::string& address);

        std::string toString() const;

    private:
        std::string address;
};