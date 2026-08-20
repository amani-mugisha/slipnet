#include "core/network_state.hpp"

void NetworkState::clear()
{
    hosts.clear();
    host_ports.clear();
    services.clear();
}

void NetworkState::addHost(const HostInfo& host)
{
    for (auto& existing : hosts)
    {
        if (existing.ip == host.ip)
        {
            existing = host;
            return;
        }
    }

    hosts.push_back(host);
}

const std::vector<HostInfo>&
NetworkState::getHosts() const
{
    return hosts;
}

std::size_t NetworkState::getHostCount() const
{
    return hosts.size();
}

std::size_t NetworkState::getOnlineHostCount() const
{
    std::size_t count = 0;

    for (const auto& host : hosts)
    {
        if (host.online)
        {
            ++count;
        }
    }

    return count;
}

void NetworkState::addPort(
    const std::string& ip,
    const PortInfo& port
)
{
    for (auto& host : host_ports)
    {
        if (host.ip != ip)
        {
            continue;
        }

        for (auto& existing : host.ports)
        {
            if (existing.port == port.port)
            {
                existing = port;
                return;
            }
        }

        host.ports.push_back(port);
        return;
    }

    HostPorts newHost;

    newHost.ip = ip;
    newHost.ports.push_back(port);

    host_ports.push_back(newHost);
}

const std::vector<PortInfo>&
NetworkState::getPorts(
    const std::string& ip
) const
{
    static const std::vector<PortInfo> empty;

    for (const auto& host : host_ports)
    {
        if (host.ip == ip)
        {
            return host.ports;
        }
    }

    return empty;
}

void NetworkState::addService(
    const ServiceInfo& service
)
{
    for (auto& existing : services)
    {
        if (
            existing.ip == service.ip &&
            existing.port == service.port
        )
        {
            existing = service;
            return;
        }
    }

    services.push_back(service);
}

const std::vector<ServiceInfo>&
NetworkState::getServices() const
{
    return services;
}