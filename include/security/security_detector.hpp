#pragma once

#include <string>
#include <vector>

#include "core/network_state.hpp"
#include "security/alert.hpp"

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

    void checkRemoteAdministration(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkManagementServices(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkFileSharing(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkCleartextServices(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkHighRiskServices(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkServiceExposure(
        const std::string& ip,
        const std::vector<ServiceInfo>& services,
        std::vector<Alert>& alerts
    ) const;

    void checkServicePortConsistency(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        const std::vector<ServiceInfo>& services,
        std::vector<Alert>& alerts
    ) const;

    void checkAttackSurface(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;

    void checkAdministrativeExposure(
        const std::string& ip,
        const std::vector<PortInfo>& ports,
        std::vector<Alert>& alerts
    ) const;
};