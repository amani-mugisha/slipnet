#pragma once

#include <string>


struct Alert
{
    /*
     * Machine-readable security finding type.
     *
     * Examples:
     *
     * TELNET_EXPOSED
     * FTP_EXPOSED
     * SMB_EXPOSED
     * RDP_EXPOSED
     */
    std::string type;


    /*
     * Human-readable explanation
     * of the security finding.
     */
    std::string description;


    /*
     * Severity:
     *
     * 0 = Informational
     * 1 = Low
     * 2 = Medium
     * 3 = High
     */
    int severity = 0;
};