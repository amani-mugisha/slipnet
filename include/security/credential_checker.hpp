#pragma once

#include "core/network_state.hpp"

#include <string>
#include <vector>

enum class CredentialRisk
{
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

struct CredentialFinding
{
    std::string host;
    int port = 0;

    std::string service;
    std::string version;

    std::string id;
    std::string title;
    std::string description;
    std::string evidence;
    std::string remediation;

    CredentialRisk risk =
        CredentialRisk::INFO;

    int confidence = 0;
};

class CredentialChecker
{
public:

    std::vector<CredentialFinding>
    check(
        const std::vector<ServiceInfo>& services
    ) const;

private:

    void checkPlaintextAuthentication(
        const ServiceInfo& service,
        std::vector<CredentialFinding>& findings
    ) const;

    void checkRemoteAuthenticationExposure(
        const ServiceInfo& service,
        std::vector<CredentialFinding>& findings
    ) const;

    void checkDatabaseAuthenticationExposure(
        const ServiceInfo& service,
        std::vector<CredentialFinding>& findings
    ) const;

    static CredentialFinding makeFinding(
        const ServiceInfo& service,
        CredentialRisk risk,
        const std::string& id,
        const std::string& title,
        const std::string& description,
        const std::string& evidence,
        const std::string& remediation,
        int confidence
    );
};