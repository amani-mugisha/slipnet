#pragma once

#include <string>
#include <vector>

#include "core/network_state.hpp"
#include "security/alert.hpp"

/*
 * SlipNet Security Detector
 *
 * Passive security-analysis engine.
 *
 * IMPORTANT:
 * This component does not perform network connections,
 * authentication attempts, exploitation, or vulnerability
 * probing.
 *
 * It analyzes information already collected by SlipNet:
 *
 *     ip|:seek
 *     port|:scan
 *     svc|:detect
 *
 * The same implementation is therefore usable on both
 * Linux and Windows.
 */
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