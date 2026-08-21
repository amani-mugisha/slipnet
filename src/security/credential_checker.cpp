#include "security/credential_checker.hpp"

#include <algorithm>

CredentialFinding
CredentialChecker::makeFinding(
    const ServiceInfo& service,
    CredentialRisk risk,
    const std::string& id,
    const std::string& title,
    const std::string& description,
    const std::string& evidence,
    const std::string& remediation
)
{
    CredentialFinding finding;

    finding.host = service.ip;
    finding.port = service.port;
    finding.service = service.service;

    finding.risk = risk;

    finding.id = id;
    finding.title = title;
    finding.description = description;
    finding.evidence = evidence;
    finding.remediation = remediation;

    return finding;
}

void CredentialChecker::analyzeService(
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
                    "Credentials may traverse an insecure FTP channel",
                    "FTP does not provide modern transport protection "
                    "by itself.",
                    "FTP detected on TCP/21.",
                    "Use SFTP or FTPS and disable plaintext FTP."
                )
            );
            break;

        case 23:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::CRITICAL,
                    "SLP-CRED-TELNET",
                    "Credentials exposed through Telnet",
                    "Telnet provides no secure transport for "
                    "authentication credentials.",
                    "Telnet detected on TCP/23.",
                    "Disable Telnet and use SSH."
                )
            );
            break;

        case 80:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::MEDIUM,
                    "SLP-CRED-HTTP",
                    "HTTP may expose authentication data",
                    "Credentials submitted over HTTP may be "
                    "transmitted without TLS.",
                    "HTTP service detected on TCP/80.",
                    "Use HTTPS for authentication and sensitive data."
                )
            );
            break;

        case 110:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::MEDIUM,
                    "SLP-CRED-POP3",
                    "POP3 credential protection should be reviewed",
                    "Plain POP3 may transmit authentication data "
                    "without encryption.",
                    "POP3 detected on TCP/110.",
                    "Prefer POP3S or STARTTLS with strong TLS settings."
                )
            );
            break;

        case 143:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::MEDIUM,
                    "SLP-CRED-IMAP",
                    "IMAP credential protection should be reviewed",
                    "Plain IMAP may transmit authentication data "
                    "without encryption.",
                    "IMAP detected on TCP/143.",
                    "Prefer IMAPS or STARTTLS."
                )
            );
            break;

        case 3389:
            findings.push_back(
                makeFinding(
                    service,
                    CredentialRisk::HIGH,
                    "SLP-CRED-RDP",
                    "Remote authentication surface exposed",
                    "RDP presents a remote authentication surface "
                    "that should be strongly restricted.",
                    "RDP detected on TCP/3389.",
                    "Restrict RDP using network controls and require "
                    "strong authentication."
                )
            );
            break;

        default:
            break;
    }
}

std::vector<CredentialFinding>
CredentialChecker::analyze(
    const std::vector<ServiceInfo>& services
) const
{
    std::vector<CredentialFinding> findings;

    for (const auto& service : services)
    {
        analyzeService(
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

            return a.host < b.host;
        }
    );

    return findings;
}