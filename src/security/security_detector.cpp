#include "security/security_detector.hpp"

#include <algorithm>
#include <cctype>
#include <string>


namespace
{

bool isOpen(
    const PortInfo& port
)
{
    return port.open;
}


bool containsInsensitive(
    const std::string& value,
    const std::string& search
)
{
    if (search.empty())
    {
        return true;
    }

    if (value.size() < search.size())
    {
        return false;
    }

    for (
        std::size_t i = 0;
        i + search.size() <= value.size();
        ++i
    )
    {
        bool match = true;

        for (
            std::size_t j = 0;
            j < search.size();
            ++j
        )
        {
            const auto left =
                static_cast<unsigned char>(
                    value[i + j]
                );

            const auto right =
                static_cast<unsigned char>(
                    search[j]
                );

            if (
                std::tolower(left) !=
                std::tolower(right)
            )
            {
                match = false;
                break;
            }
        }

        if (match)
        {
            return true;
        }
    }

    return false;
}


void addAlert(
    std::vector<Alert>& alerts,
    const std::string& type,
    const std::string& description,
    int severity
)
{
    /*
     * Prevent duplicate findings of the same
     * type for the same analysis.
     */
    for (const auto& existing : alerts)
    {
        if (
            existing.type == type &&
            existing.description == description
        )
        {
            return;
        }
    }

    Alert alert;

    alert.type = type;
    alert.description = description;
    alert.severity = severity;

    alerts.push_back(alert);
}

} // namespace


std::vector<Alert>
SecurityDetector::analyze(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    const std::vector<ServiceInfo>& services
) const
{
    std::vector<Alert> alerts;

    /*
     * Protocol exposure
     */
    checkLegacyProtocols(
        ip,
        ports,
        alerts
    );

    /*
     * Database exposure
     */
    checkExposedDatabases(
        ip,
        ports,
        alerts
    );

    /*
     * Remote administration
     */
    checkRemoteAdministration(
        ip,
        ports,
        alerts
    );

    /*
     * Management infrastructure
     */
    checkManagementServices(
        ip,
        ports,
        alerts
    );

    /*
     * File sharing / Windows-oriented exposure
     */
    checkFileSharing(
        ip,
        ports,
        alerts
    );

    /*
     * Clear-text application protocols
     */
    checkCleartextServices(
        ip,
        ports,
        alerts
    );

    /*
     * High-risk infrastructure services
     */
    checkHighRiskServices(
        ip,
        ports,
        alerts
    );

    /*
     * Services discovered by svc|:detect
     */
    checkServiceExposure(
        ip,
        services,
        alerts
    );

    /*
     * Detect suspicious service/port combinations.
     */
    checkServicePortConsistency(
        ip,
        ports,
        services,
        alerts
    );

    /*
     * General attack-surface measurement.
     */
    checkAttackSurface(
        ip,
        ports,
        alerts
    );

    /*
     * Administrative exposure summary.
     */
    checkAdministrativeExposure(
        ip,
        ports,
        alerts
    );

    /*
     * Highest severity first.
     */
    std::sort(
        alerts.begin(),
        alerts.end(),
        [](
            const Alert& left,
            const Alert& right
        )
        {
            if (
                left.severity !=
                right.severity
            )
            {
                return
                    left.severity >
                    right.severity;
            }

            return left.type <
                   right.type;
        }
    );

    return alerts;
}


/*
 * ============================================================
 * LEGACY PROTOCOLS
 * ============================================================
 */

void SecurityDetector::checkLegacyProtocols(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    for (const auto& port : ports)
    {
        if (!isOpen(port))
        {
            continue;
        }

        if (port.port == 23)
        {
            addAlert(
                alerts,
                "TELNET_EXPOSED",
                "Telnet is exposed on " +
                    ip +
                    " through TCP port 23. "
                    "Telnet transmits credentials and "
                    "session data without modern encryption.",
                3
            );
        }
        else if (port.port == 21)
        {
            addAlert(
                alerts,
                "FTP_EXPOSED",
                "FTP is exposed on " +
                    ip +
                    " through TCP port 21. "
                    "Standard FTP does not provide "
                    "encrypted transport.",
                2
            );
        }
        else if (port.port == 69)
        {
            addAlert(
                alerts,
                "TFTP_EXPOSED",
                "TFTP is exposed on " +
                    ip +
                    " through UDP port 69. "
                    "TFTP provides minimal authentication "
                    "and should normally be restricted.",
                3
            );
        }
    }
}


/*
 * ============================================================
 * DATABASE EXPOSURE
 * ============================================================
 */

void SecurityDetector::checkExposedDatabases(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    for (const auto& port : ports)
    {
        if (!isOpen(port))
        {
            continue;
        }

        switch (port.port)
        {
            case 3306:
                addAlert(
                    alerts,
                    "DATABASE_EXPOSED",
                    "MySQL/MariaDB appears exposed on " +
                        ip +
                        " through TCP port 3306.",
                    3
                );
                break;

            case 5432:
                addAlert(
                    alerts,
                    "DATABASE_EXPOSED",
                    "PostgreSQL appears exposed on " +
                        ip +
                        " through TCP port 5432.",
                    3
                );
                break;

            case 27017:
                addAlert(
                    alerts,
                    "DATABASE_EXPOSED",
                    "MongoDB appears exposed on " +
                        ip +
                        " through TCP port 27017.",
                    3
                );
                break;

            case 6379:
                addAlert(
                    alerts,
                    "CACHE_EXPOSED",
                    "Redis appears exposed on " +
                        ip +
                        " through TCP port 6379. "
                        "Redis should normally be restricted "
                        "to trusted network segments.",
                    3
                );
                break;

            case 9200:
                addAlert(
                    alerts,
                    "SEARCH_ENGINE_EXPOSED",
                    "Elasticsearch appears exposed on " +
                        ip +
                        " through TCP port 9200. "
                        "Administrative interfaces should "
                        "not normally be publicly reachable.",
                    3
                );
                break;

            default:
                break;
        }
    }
}


/*
 * ============================================================
 * REMOTE ADMINISTRATION
 * ============================================================
 */

void SecurityDetector::checkRemoteAdministration(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    for (const auto& port : ports)
    {
        if (!isOpen(port))
        {
            continue;
        }

        if (port.port == 22)
        {
            addAlert(
                alerts,
                "SSH_EXPOSED",
                "SSH is exposed on " +
                    ip +
                    " through TCP port 22. "
                    "Restrict access and use strong "
                    "authentication controls.",
                1
            );
        }
        else if (port.port == 3389)
        {
            addAlert(
                alerts,
                "RDP_EXPOSED",
                "Remote Desktop Protocol is exposed on " +
                    ip +
                    " through TCP port 3389. "
                    "RDP should be protected by network "
                    "access controls and strong authentication.",
                3
            );
        }
        else if (port.port == 5900)
        {
            addAlert(
                alerts,
                "VNC_EXPOSED",
                "VNC is exposed on " +
                    ip +
                    " through TCP port 5900. "
                    "Remote graphical administration should "
                    "be restricted to trusted networks.",
                2
            );
        }
    }
}


/*
 * ============================================================
 * MANAGEMENT SERVICES
 * ============================================================
 */

void SecurityDetector::checkManagementServices(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    for (const auto& port : ports)
    {
        if (!isOpen(port))
        {
            continue;
        }

        if (port.port == 161)
        {
            addAlert(
                alerts,
                "SNMP_EXPOSED",
                "SNMP appears exposed on " +
                    ip +
                    " through UDP port 161. "
                    "SNMP configuration and community access "
                    "should be restricted.",
                2
            );
        }
        else if (port.port == 2375)
        {
            addAlert(
                alerts,
                "DOCKER_API_EXPOSED",
                "The Docker API appears exposed on " +
                    ip +
                    " through TCP port 2375. "
                    "An unauthenticated Docker API can provide "
                    "high-impact administrative access.",
                3
            );
        }
        else if (port.port == 2376)
        {
            addAlert(
                alerts,
                "DOCKER_TLS_API_EXPOSED",
                "The Docker API TLS endpoint appears exposed on " +
                    ip +
                    " through TCP port 2376. "
                    "Verify certificate and authorization controls.",
                2
            );
        }
    }
}


/*
 * ============================================================
 * FILE SHARING
 * ============================================================
 */

void SecurityDetector::checkFileSharing(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    bool smb445 = false;
    bool netbios139 = false;

    for (const auto& port : ports)
    {
        if (!isOpen(port))
        {
            continue;
        }

        if (port.port == 445)
        {
            smb445 = true;
        }

        if (port.port == 139)
        {
            netbios139 = true;
        }
    }

    if (smb445)
    {
        addAlert(
            alerts,
            "SMB_EXPOSED",
            "SMB is exposed on " +
                ip +
                " through TCP port 445. "
                "File-sharing services should be restricted "
                "to trusted networks.",
            3
        );
    }

    if (netbios139)
    {
        addAlert(
            alerts,
            "NETBIOS_EXPOSED",
            "NetBIOS session service is exposed on " +
                ip +
                " through TCP port 139.",
            2
        );
    }
}


/*
 * ============================================================
 * CLEARTEXT SERVICES
 * ============================================================
 */

void SecurityDetector::checkCleartextServices(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    for (const auto& port : ports)
    {
        if (!isOpen(port))
        {
            continue;
        }

        switch (port.port)
        {
            case 25:
                addAlert(
                    alerts,
                    "SMTP_EXPOSED",
                    "SMTP is exposed on " +
                        ip +
                        " through TCP port 25. "
                        "Verify relay restrictions and "
                        "mail-service security configuration.",
                    1
                );
                break;

            case 110:
                addAlert(
                    alerts,
                    "POP3_EXPOSED",
                    "POP3 is exposed on " +
                        ip +
                        " through TCP port 110. "
                        "Prefer encrypted mail access where supported.",
                    2
                );
                break;

            case 143:
                addAlert(
                    alerts,
                    "IMAP_EXPOSED",
                    "IMAP is exposed on " +
                        ip +
                        " through TCP port 143. "
                        "Verify that encrypted authentication "
                        "is enforced.",
                    1
                );
                break;

            case 80:
                addAlert(
                    alerts,
                    "HTTP_EXPOSED",
                    "HTTP is exposed on " +
                        ip +
                        " through TCP port 80. "
                        "If sensitive applications are hosted "
                        "here, HTTPS should be preferred.",
                    1
                );
                break;

            default:
                break;
        }
    }
}


/*
 * ============================================================
 * HIGH-RISK INFRASTRUCTURE SERVICES
 * ============================================================
 */

void SecurityDetector::checkHighRiskServices(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    for (const auto& port : ports)
    {
        if (!isOpen(port))
        {
            continue;
        }

        if (port.port == 111)
        {
            addAlert(
                alerts,
                "RPC_EXPOSED",
                "RPC portmapper appears exposed on " +
                    ip +
                    " through TCP/UDP port 111.",
                2
            );
        }
        else if (port.port == 2049)
        {
            addAlert(
                alerts,
                "NFS_EXPOSED",
                "NFS appears exposed on " +
                    ip +
                    " through port 2049. "
                    "Verify export restrictions and "
                    "network access controls.",
                3
            );
        }
        else if (port.port == 5000)
        {
            addAlert(
                alerts,
                "APPLICATION_SERVICE_EXPOSED",
                "A service is exposed on " +
                    ip +
                    " through TCP port 5000. "
                    "Verify that the application interface "
                    "is intended to be network accessible.",
                1
            );
        }
    }
}


/*
 * ============================================================
 * SERVICE EXPOSURE
 * ============================================================
 */

void SecurityDetector::checkServiceExposure(
    const std::string& ip,
    const std::vector<ServiceInfo>& services,
    std::vector<Alert>& alerts
) const
{
    for (const auto& service : services)
    {
        if (service.ip != ip)
        {
            continue;
        }

        if (service.service.empty())
        {
            continue;
        }

        /*
         * We intentionally do NOT claim that a particular
         * software version is vulnerable here.
         *
         * svc|:detect must provide reliable version data
         * before version intelligence is added.
         */
        if (
            containsInsensitive(
                service.service,
                "telnet"
            )
        )
        {
            addAlert(
                alerts,
                "LEGACY_SERVICE_DETECTED",
                "Service detection identified Telnet on " +
                    ip +
                    " port " +
                    std::to_string(service.port) +
                    ".",
                3
            );
        }
    }
}


/*
 * ============================================================
 * SERVICE / PORT CONSISTENCY
 * ============================================================
 */

void SecurityDetector::checkServicePortConsistency(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    const std::vector<ServiceInfo>& services,
    std::vector<Alert>& alerts
) const
{
    for (const auto& service : services)
    {
        if (service.ip != ip)
        {
            continue;
        }

        bool matchingOpenPort = false;

        for (const auto& port : ports)
        {
            if (
                port.open &&
                port.port == service.port
            )
            {
                matchingOpenPort = true;
                break;
            }
        }

        if (!matchingOpenPort)
        {
            addAlert(
                alerts,
                "SERVICE_STATE_MISMATCH",
                "Service information reports " +
                    service.service +
                    " on port " +
                    std::to_string(service.port) +
                    ", but the corresponding port is not "
                    "currently recorded as open.",
                1
            );
        }
    }
}


/*
 * ============================================================
 * ATTACK SURFACE
 * ============================================================
 */

void SecurityDetector::checkAttackSurface(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    int openPorts = 0;

    for (const auto& port : ports)
    {
        if (port.open)
        {
            ++openPorts;
        }
    }

    if (openPorts >= 20)
    {
        addAlert(
            alerts,
            "VERY_LARGE_ATTACK_SURFACE",
            "Host " +
                ip +
                " has " +
                std::to_string(openPorts) +
                " open TCP ports. "
                "Review whether all exposed services are required.",
            3
        );
    }
    else if (openPorts >= 10)
    {
        addAlert(
            alerts,
            "LARGE_ATTACK_SURFACE",
            "Host " +
                ip +
                " has " +
                std::to_string(openPorts) +
                " open TCP ports. "
                "Reducing unnecessary exposed services can "
                "reduce attack surface.",
            2
        );
    }
}


/*
 * ============================================================
 * ADMINISTRATIVE EXPOSURE
 * ============================================================
 */

void SecurityDetector::checkAdministrativeExposure(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    bool ssh = false;
    bool rdp = false;
    bool smb = false;
    bool vnc = false;

    for (const auto& port : ports)
    {
        if (!port.open)
        {
            continue;
        }

        switch (port.port)
        {
            case 22:
                ssh = true;
                break;

            case 3389:
                rdp = true;
                break;

            case 445:
                smb = true;
                break;

            case 5900:
                vnc = true;
                break;

            default:
                break;
        }
    }

    const int administrativeServices =
        static_cast<int>(ssh) +
        static_cast<int>(rdp) +
        static_cast<int>(smb) +
        static_cast<int>(vnc);

    if (administrativeServices >= 2)
    {
        addAlert(
            alerts,
            "MULTIPLE_ADMIN_SERVICES",
            "Host " +
                ip +
                " exposes multiple administrative or "
                "remote-management services. "
                "Review access controls and minimize "
                "unnecessary remote administration interfaces.",
            2
        );
    }
}