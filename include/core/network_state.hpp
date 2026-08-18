#pragma once

#include <cstddef>
#include <string>
#include <vector>


struct HostInfo
{
    std::string ip;
    std::string hostname;

    bool online = false;

    double latency_ms = 0.0;

    std::string status;
};


struct PortInfo
{
    int port = 0;

    bool open = false;

    std::string protocol;

    std::string service;
};


struct ServiceInfo
{
    std::string ip;

    int port = 0;

    std::string protocol;

    std::string service;

    std::string version;
};


class NetworkState
{
public:

    void clear();


    // Hosts
    void addHost(
        const HostInfo& host
    );

    const std::vector<HostInfo>&
    getHosts() const;

    std::size_t
    getHostCount() const;

    std::size_t
    getOnlineHostCount() const;


    // Ports
    void addPort(
        const std::string& ip,
        const PortInfo& port
    );

    const std::vector<PortInfo>&
    getPorts(
        const std::string& ip
    ) const;


    // Services
    void addService(
        const ServiceInfo& service
    );

    const std::vector<ServiceInfo>&
    getServices() const;


private:

    std::vector<HostInfo> hosts;

    struct HostPorts
    {
        std::string ip;

        std::vector<PortInfo> ports;
    };

    std::vector<HostPorts> host_ports;

    std::vector<ServiceInfo> services;
};