#include "network/ip_address.hpp"

IPAddress::IPAddress(const std::string& address) : address(address) {

}
std::string IPAddress::toString() const {
    return address;
}