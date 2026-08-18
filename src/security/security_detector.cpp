#include "security/security_detector.hpp"

#include <string>


std::vector<Alert>
SecurityDetector::analyze(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    const std::vector<ServiceInfo>& services
) const
{
    std::vector<Alert> alerts;


    /*
     * ========================================================
     * LEGACY / INSECURE PROTOCOLS
     * ========================================================
     */

    checkLegacyProtocols(
        ip,
        ports,
        alerts
    );


    /*
     * ========================================================
     * EXPOSED DATABASE SERVICES
     * ========================================================
     */

    checkExposedDatabases(
        ip,
        ports,
        alerts
    );


    /*
     * ========================================================
     * REMOTE ADMINISTRATION
     * ========================================================
     */

    checkRemoteAdmin(
        ip,
        ports,
        alerts
    );


    /*
     * ========================================================
     * SERVICE VERSION ANALYSIS
     * ========================================================
     */

    checkKnownVulnerableVersions(
        ip,
        services,
        alerts
    );


    /*
     * ========================================================
     * ATTACK SURFACE ANALYSIS
     * ========================================================
     */

    checkAttackSurface(
        ip,
        ports,
        alerts
    );


    return alerts;
}


/*
 * ============================================================
 * Legacy protocol detection
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
        if (!port.open)
        {
            continue;
        }


        /*
         * Telnet
         */

        if (port.port == 23)
        {
            Alert alert;

            alert.type =
                "TELNET_EXPOSED";

            alert.description =
                "Telnet is exposed on " +
                ip +
                " through TCP port 23.";

            alert.severity = 3;

            alerts.push_back(alert);
        }


        /*
         * FTP
         */

        else if (port.port == 21)
        {
            Alert alert;

            alert.type =
                "FTP_EXPOSED";

            alert.description =
                "FTP is exposed on " +
                ip +
                " through TCP port 21.";

            alert.severity = 2;

            alerts.push_back(alert);
        }
    }
}


/*
 * ============================================================
 * Database exposure
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
        if (!port.open)
        {
            continue;
        }


        /*
         * MySQL / MariaDB
         */

        if (port.port == 3306)
        {
            Alert alert;

            alert.type =
                "DATABASE_EXPOSED";

            alert.description =
                "MySQL/MariaDB database service "
                "appears exposed on " +
                ip +
                " through TCP port 3306.";

            alert.severity = 3;

            alerts.push_back(alert);
        }


        /*
         * PostgreSQL
         */

        else if (port.port == 5432)
        {
            Alert alert;

            alert.type =
                "DATABASE_EXPOSED";

            alert.description =
                "PostgreSQL database service "
                "appears exposed on " +
                ip +
                " through TCP port 5432.";

            alert.severity = 3;

            alerts.push_back(alert);
        }


        /*
         * MongoDB
         */

        else if (port.port == 27017)
        {
            Alert alert;

            alert.type =
                "DATABASE_EXPOSED";

            alert.description =
                "MongoDB service appears exposed "
                "on " +
                ip +
                " through TCP port 27017.";

            alert.severity = 3;

            alerts.push_back(alert);
        }
    }
}


/*
 * ============================================================
 * Remote administration detection
 * ============================================================
 */

void SecurityDetector::checkRemoteAdmin(
    const std::string& ip,
    const std::vector<PortInfo>& ports,
    std::vector<Alert>& alerts
) const
{
    for (const auto& port : ports)
    {
        if (!port.open)
        {
            continue;
        }


        /*
         * SSH
         */

        if (port.port == 22)
        {
            Alert alert;

            alert.type =
                "SSH_EXPOSED";

            alert.description =
                "SSH is exposed on " +
                ip +
                " through TCP port 22. "
                "Ensure strong authentication "
                "and access restrictions are used.";

            alert.severity = 1;

            alerts.push_back(alert);
        }


        /*
         * RDP
         */

        else if (port.port == 3389)
        {
            Alert alert;

            alert.type =
                "RDP_EXPOSED";

            alert.description =
                "Remote Desktop is exposed on " +
                ip +
                " through TCP port 3389.";

            alert.severity = 2;

            alerts.push_back(alert);
        }


        /*
         * SMB
         */

        else if (port.port == 445)
        {
            Alert alert;

            alert.type =
                "SMB_EXPOSED";

            alert.description =
                "SMB is exposed on " +
                ip +
                " through TCP port 445.";

            alert.severity = 3;

            alerts.push_back(alert);
        }
    }
}


/*
 * ============================================================
 * Service-version analysis
 * ============================================================
 *
 * We don't assume a vulnerability here yet.
 * This function is intentionally conservative until the
 * service detector provides reliable version information.
 */

void SecurityDetector::checkKnownVulnerableVersions(
    const std::string& ip,
    const std::vector<ServiceInfo>& services,
    std::vector<Alert>& alerts
) const
{
    (void)ip;
    (void)services;

    /*
     * Version-based vulnerability intelligence
     * will be implemented after svc|:detect
     * provides structured version information.
     */
}


/*
 * ============================================================
 * Attack-surface analysis
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


    /*
     * A host exposing many ports has a larger
     * externally reachable attack surface.
     */

    if (openPorts >= 10)
    {
        Alert alert;

        alert.type =
            "LARGE_ATTACK_SURFACE";

        alert.description =
            "Host " +
            ip +
            " has " +
            std::to_string(openPorts) +
            " open TCP ports.";

        alert.severity = 2;

        alerts.push_back(alert);
    }
}