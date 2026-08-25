#include "network/dns_resolver.hpp"
#include "platform/dns.hpp"

DNSResult DNSResolver::resolve(
    const std::string& input
) const
{
    DNSResult result;

    result.input = input;

    const auto platformResult =
        slipnet::platform::resolveDNS(input);

    result.canonicalName =
        platformResult.canonicalName;

    result.addresses =
        platformResult.addresses;

    result.reverseName =
        platformResult.reverseName;

    /*
     * Forward DNS:
     * success when at least one address was resolved.
     *
     * Reverse DNS:
     * success when a PTR hostname was resolved.
     *
     * Do NOT mark an IP as fully resolved merely because
     * the reverse lookup completed without an error.
     */
    if (isIPAddress(input))
    {
        result.success =
            !result.reverseName.empty();
    }
    else
    {
        result.success =
            !result.addresses.empty();
    }

    return result;
}

bool DNSResolver::isIPAddress(
    const std::string& value
) const
{
    return slipnet::platform::isIPAddress(value);
}