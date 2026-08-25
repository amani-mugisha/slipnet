#include "security/credential_checker.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace
{

std::string lower(
    std::string value
)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                std::tolower(c)
            );
        }
    );

    return value;
}

bool contains(
    const std::string& value,
    const std::string& search
)
{
    return lower(value).find(
        lower(search)
    ) != std::string::npos;
}

} // namespace


CredentialFinding
CredentialChecker::makeFinding(
    const ServiceInfo& service,
    CredentialRisk risk,
    const std::string& id,
    const std::string& title,
    const std::string& description,
    const std::string& evidence,
    const std::string& remediation,
    int confidence
)
{
    CredentialFinding finding;

    finding.host =
        service.ip;

    finding.port =
        service.port;

    finding.service =
        service.service;

    finding.version =
        service.version;

    finding.risk =
        risk;

    finding.id =
        id;

    finding.title =
        title;

    finding.description =
        description;

    finding.evidence =
        evidence;

    finding.remediation =
        remediation;

    finding.confidence =
        std::max(
            0,
            std::min(
                100,
                confidence
            )
        );

    return finding;
}


void CredentialChecker::checkPlaintextAuthentication(
    const ServiceInfo& service,
    std::vector<CredentialFinding>& findings
) const
{
    switch (service.port)
    {
        case 21:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-FTP",
                    "FTP authentication may expose credentials",
                    "Traditional FTP does not provide transport "
                    "encryption by itself. Authentication material "
                    "may therefore be transmitted without protection.",
                    "TCP/21 is reachable and identified as FTP.",
                    "Prefer SFTP or FTPS and restrict FTP access "
                    "to trusted network segments.",
                    95
                )
            );
            break;

        case 23:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::CRITICAL,
                    "SLP-CRED-TELNET",
                    "Telnet authentication may expose credentials",
                    "Telnet provides no native transport encryption. "
                    "Credentials and session traffic may be exposed "
                    "to network observers.",
                    "TCP/23 is reachable.",
                    "Disable Telnet and use SSH or another encrypted "
                    "remote administration protocol.",
                    98
                )
            );
            break;

        case 25:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::MEDIUM,
                    "SLP-CRED-SMTP",
                    "SMTP authentication exposure",
                    "SMTP services may support authentication over "
                    "unencrypted or improperly protected connections.",
                    "TCP/25 is reachable and may provide SMTP service.",
                    "Require TLS for authenticated SMTP sessions and "
                    "disable insecure authentication mechanisms.",
                    80
                )
            );
            break;

        case 110:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-POP3",
                    "POP3 authentication may expose credentials",
                    "Traditional POP3 does not inherently protect "
                    "authentication traffic with encryption.",
                    "TCP/110 is reachable.",
                    "Prefer POP3S or enforce STARTTLS with secure "
                    "authentication policies.",
                    92
                )
            );
            break;

        case 143:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-IMAP",
                    "IMAP authentication may expose credentials",
                    "Traditional IMAP can expose authentication "
                    "material when TLS is not enforced.",
                    "TCP/143 is reachable.",
                    "Require TLS/STARTTLS and disable insecure "
                    "authentication where possible.",
                    90
                )
            );
            break;

        default:
            break;
    }
}


void CredentialChecker::checkRemoteAuthenticationExposure(
    const ServiceInfo& service,
    std::vector<CredentialFinding>& findings
) const
{
    switch (service.port)
    {
        case 22:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::LOW,
                    "SLP-CRED-SSH",
                    "SSH authentication surface exposed",
                    "SSH provides encrypted authentication, but an "
                    "exposed remote authentication service increases "
                    "the authentication attack surface.",
                    "TCP/22 is reachable and identified as SSH.",
                    "Restrict SSH access using firewall rules, VPN "
                    "access, key-based authentication and appropriate "
                    "rate-limiting controls.",
                    90
                )
            );
            break;

        case 3389:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-RDP",
                    "RDP authentication surface exposed",
                    "Remote Desktop exposes a remote authentication "
                    "interface that should normally be restricted "
                    "to trusted networks.",
                    "TCP/3389 is reachable.",
                    "Restrict RDP through VPN or firewall policies "
                    "and enforce strong authentication controls.",
                    94
                )
            );
            break;

        case 445:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-SMB",
                    "SMB authentication surface exposed",
                    "SMB provides a network authentication surface "
                    "that can increase credential-related attack risk "
                    "when exposed to untrusted networks.",
                    "TCP/445 is reachable.",
                    "Restrict SMB to trusted networks and enforce "
                    "modern SMB security policies.",
                    93
                )
            );
            break;

        default:
            break;
    }
}


void CredentialChecker::checkDatabaseAuthenticationExposure(
    const ServiceInfo& service,
    std::vector<CredentialFinding>& findings
) const
{
    switch (service.port)
    {
        case 3306:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-MYSQL",
                    "MySQL authentication endpoint exposed",
                    "A remotely reachable database authentication "
                    "service increases the risk of credential attacks "
                    "and unauthorized database access.",
                    "TCP/3306 is reachable.",
                    "Restrict MySQL access to trusted application "
                    "hosts and require strong authentication.",
                    93
                )
            );
            break;

        case 5432:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-POSTGRES",
                    "PostgreSQL authentication endpoint exposed",
                    "A remotely reachable PostgreSQL authentication "
                    "service increases the database attack surface.",
                    "TCP/5432 is reachable.",
                    "Restrict PostgreSQL access using network controls "
                    "and strong authentication policies.",
                    93
                )
            );
            break;

        case 6379:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-REDIS",
                    "Redis authentication surface exposed",
                    "An exposed Redis service may present a serious "
                    "authentication and unauthorized-access risk "
                    "depending on its configuration.",
                    "TCP/6379 is reachable.",
                    "Restrict Redis to trusted hosts and enforce "
                    "authentication and network access controls.",
                    90
                )
            );
            break;

        case 27017:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-MONGO",
                    "MongoDB authentication surface exposed",
                    "A remotely reachable MongoDB service increases "
                    "the risk of unauthorized database access when "
                    "authentication or network controls are weak.",
                    "TCP/27017 is reachable.",
                    "Restrict MongoDB access and enforce authentication "
                    "with appropriate network segmentation.",
                    90
                )
            );
            break;

        default:
            break;
    }
}


std::vector<CredentialFinding>
CredentialChecker::check(
    const std::vector<ServiceInfo>& services
) const
{
    std::vector<CredentialFinding> findings;

    for (const auto& service : services)
    {
        checkPlaintextAuthentication(
            service,
            findings
        );

        checkRemoteAuthenticationExposure(
            service,
            findings
        );

        checkDatabaseAuthenticationExposure(
            service,
            findings
        );
    }

    std::sort(
        findings.begin(),
        findings.end(),
        [](const CredentialFinding& a,
           const CredentialFinding& b)
        {
            if (a.risk != b.risk)
            {
                return static_cast<int>(a.risk) >
                       static_cast<int>(b.risk);
            }

            if (a.host != b.host)
            {
                return a.host < b.host;
            }

            return a.port < b.port;
        }
    );

    return findings;
}