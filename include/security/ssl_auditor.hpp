#pragma once

#include <string>

#include <vector>

enum class SSLSeverity
{
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

struct SSLFinding
{
    SSLSeverity severity = SSLSeverity::INFO;

    std::string id;
    std::string title;
    std::string description;
    std::string evidence;
    std::string remediation;

    int confidence = 0;
};

struct SSLAuditResult
{
    bool connected = false;
    bool tlsEstablished = false;

    std::string host;
    int port = 443;

    std::string tlsVersion;
    std::string cipher;

    std::string subject;
    std::string issuer;

    std::string validFrom;
    std::string validUntil;

    bool certificateValid = false;
    bool certificateExpired = false;
    bool selfSigned = false;

    std::vector<SSLFinding> findings;
};

class SSLAuditor
{
public:

    SSLAuditResult audit(
        const std::string& host,
        int port = 443
    ) const;

private:

    static SSLFinding makeFinding(
        SSLSeverity severity,
        const std::string& id,
        const std::string& title,
        const std::string& description,
        const std::string& evidence,
        const std::string& remediation,
        int confidence
    );

    static std::string nameFromCertificate(
        void* certificate,
        bool issuer
    );

    static std::string certificateTime(
        void* certificate,
        bool notBefore
    );
};