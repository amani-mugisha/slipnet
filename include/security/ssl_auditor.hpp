#pragma once

#include <string>
#include <vector>

enum class TLSSeverity
{
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

struct TLSFinding
{
    TLSSeverity severity =
        TLSSeverity::INFO;

    std::string id;
    std::string title;
    std::string description;
    std::string remediation;
};

struct SSLAuditResult
{
    bool success = false;

    std::string host;

    int port = 443;

    std::string protocol;
    std::string cipher;

    std::string subject;
    std::string issuer;

    std::string validFrom;
    std::string validUntil;

    long daysRemaining = -1;

    bool hostnameMatch = false;
    bool certificateValid = false;

    std::vector<TLSFinding> findings;

    std::string error;
};

class SSLAuditor
{
public:

    SSLAuditResult audit(
        const std::string& target
    ) const;

private:

    static bool parseTarget(
        const std::string& input,
        std::string& host,
        int& port
    );

    static void addFindings(
        SSLAuditResult& result
    );
};