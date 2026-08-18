#pragma once

#include <string>
#include <vector>

#include "security/alert.hpp"
#include "core/network_state.hpp"


// SecurityDetector runs a set of passive, rule-based defensive checks
// against ports/services SlipNet has already discovered for a host.
// It never probes or connects itself — every check is derived purely
// from data collected by earlier scan/discovery commands.
class SecurityDetector
{
public:

    std::vector<Alert> analyze(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        const std::vector<ServiceInfo>& services
    ) const;


private:

    void checkLegacyProtocols(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkExposedDatabases(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkRemoteAdmin(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkKnownVulnerableVersions(
        const std::string& ip,
        const std::vector<ServiceInfo>& services,
        std::vector<Alert>& alerts
    ) const;

    void checkAttackSurface(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;
}; //security_detector.hpp