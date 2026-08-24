#include "cli/command_parser.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>


/*
 * ============================================================
 * Internal helper functions
 * ============================================================
 */

namespace
{
    /*
     * Remove whitespace from the beginning
     * and end of a string.
     */
    std::string trim(
        const std::string& value
    )
    {
        std::size_t start = 0;

        while (
            start < value.size()
            &&
            std::isspace(
                static_cast<unsigned char>(
                    value[start]
                )
            )
        )
        {
            ++start;
        }


        std::size_t end = value.size();

        while (
            end > start
            &&
            std::isspace(
                static_cast<unsigned char>(
                    value[end - 1]
                )
            )
        )
        {
            --end;
        }


        return value.substr(
            start,
            end - start
        );
    }


    /*
     * Convert a string to lowercase.
     */
    std::string toLower(
        std::string value
    )
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](
                unsigned char character
            )
            {
                return static_cast<char>(
                    std::tolower(character)
                );
            }
        );


        return value;
    }
}


/*
 * ============================================================
 * CommandParser::tokenize
 * ============================================================
 */

std::vector<std::string>
CommandParser::tokenize(
    const std::string& input
) const
{
    std::vector<std::string> tokens;

    std::istringstream stream(input);

    std::string token;


    while (stream >> token)
    {
        tokens.push_back(token);
    }


    return tokens;
}


/*
 * ============================================================
 * CommandParser::identifyCommand
 * ============================================================
 */

CommandType CommandParser::identifyCommand(
    const std::string& command
) const
{
    const std::string normalized =
        toLower(
            trim(command)
        );


    /*
     * --------------------------------------------------------
     * Network discovery
     * --------------------------------------------------------
     */

    if (normalized == "ip|:seek")
    {
        return CommandType::IP_SEEK;
    }


    /*
     * --------------------------------------------------------
     * Host discovery
     * --------------------------------------------------------
     */

    if (normalized == "host|:find")
    {
        return CommandType::HOST_FIND;
    }


    /*
     * --------------------------------------------------------
     * Port scanning
     * --------------------------------------------------------
     */

    if (normalized == "port|:scan")
    {
        return CommandType::PORT_SCAN;
    }


    /*
     * --------------------------------------------------------
     * Service detection
     * --------------------------------------------------------
     */

    if (normalized == "svc|:detect")
    {
        return CommandType::SERVICE_DETECT;
    }


    /*
     * --------------------------------------------------------
     * Topology
     * --------------------------------------------------------
     */

    if (normalized == "topo|:map")
    {
        return CommandType::TOPOLOGY_MAP;
    }


    /*
     * --------------------------------------------------------
     * Packet capture
     * --------------------------------------------------------
     */

    if (normalized == "pkt|:capture")
    {
        return CommandType::PACKET_CAPTURE;
    }


    /*
     * --------------------------------------------------------
     * Packet inspection
     * --------------------------------------------------------
     */

    if (normalized == "pkt|:inspect")
    {
        return CommandType::PACKET_INSPECT;
    }


    /*
     * --------------------------------------------------------
     * Network monitoring
     * --------------------------------------------------------
     */

    if (normalized == "net|:monitor")
    {
        return CommandType::NETWORK_MONITOR;
    }


    /*
     * --------------------------------------------------------
     * Network state
     * --------------------------------------------------------
     */

    if (normalized == "net|:show")
    {
        return CommandType::NETWORK_SHOW;
    }


    if (normalized == "net|:clear")
    {
        return CommandType::NETWORK_CLEAR;
    }


    /*
     * --------------------------------------------------------
     * Security
     * --------------------------------------------------------
     */

    if (normalized == "sec|:detect")
    {
        return CommandType::SECURITY_DETECT;
    }


    /*
     * --------------------------------------------------------
     * AI
     * --------------------------------------------------------
     */

    if (normalized == "ai|:analyze")
    {
        return CommandType::AI_ANALYZE;
    }


    /*
     * --------------------------------------------------------
     * Session
     * --------------------------------------------------------
     */

    if (normalized == "session|:info")
    {
        return CommandType::SESSION_INFO;
    }

    if (normalized == "mac|:resolve")
    {
        return CommandType::MAC_RESOLVE;
    }

    if (normalized == "dns|:resolve")
    {
        return CommandType::DNS_RESOLVE;
    }

    if (normalized == "os|:fingerprint")
    {
        return CommandType::OS_FINGERPRINT;
    }

    if (normalized == "banner|:grab")
    {
        return CommandType::BANNER_GRAB;
    }

    if (normalized == "subnet|:calc")
    {
        return CommandType::SUBNET_CALC;
    }
    if (normalized == "vuln|:scan")
    {
        return CommandType::VULN_SCAN;
    }

    if (normalized == "cred|:check")
    {
        return CommandType::CRED_CHECK;
    }

    if (normalized == "ssl|:audit")
    {
        return CommandType::SSL_AUDIT;
    }

    if (normalized == "firewall|:probe")
    {
        return CommandType::FIREWALL_PROBE;
    }

    if (normalized == "system|:info")
    {
        return CommandType::SYSTEM_INFO;
    }

    /*
     * --------------------------------------------------------
     * Help
     * --------------------------------------------------------
     */

    if (
        normalized == "help"
        ||
        normalized == "?"
    )
    {
        return CommandType::HELP;
    }


    /*
     * --------------------------------------------------------
     * Exit
     * --------------------------------------------------------
     *
     * "fire" is SlipNet's exit command.
     */

    if (
        normalized == "fire"
        ||
        normalized == "exit"
        ||
        normalized == "quit"
    )
    {
        return CommandType::EXIT;
    }


    /*
     * Nothing matched.
     */

    return CommandType::UNKNOWN;
}


/*
 * ============================================================
 * CommandParser::parse
 * ============================================================
 */

ParsedCommand CommandParser::parse(
    const std::string& input
) const
{
    ParsedCommand result;


    /*
     * Store original command.
     */
    result.raw = input;


    /*
     * Split input into tokens.
     */
    const auto tokens =
        tokenize(input);


    /*
     * Empty input.
     */
    if (tokens.empty())
    {
        result.type =
            CommandType::UNKNOWN;

        return result;
    }


    /*
     * First token is the command.
     */
    result.type =
        identifyCommand(
            tokens[0]
        );


    /*
     * Remaining tokens are arguments.
     */
    for (
        std::size_t i = 1;
        i < tokens.size();
        ++i
    )
    {
        result.arguments.push_back(
            tokens[i]
        );
    }


    return result;
}


/*
 * ============================================================
 * CommandUtilities::commandName
 * ============================================================
 */

std::string CommandUtilities::commandName(
    CommandType type
)
{
    switch (type)
    {
        case CommandType::IP_SEEK:
            return "ip|:seek";


        case CommandType::HOST_FIND:
            return "host|:find";


        case CommandType::PORT_SCAN:
            return "port|:scan";


        case CommandType::SERVICE_DETECT:
            return "svc|:detect";


        case CommandType::TOPOLOGY_MAP:
            return "topo|:map";


        case CommandType::PACKET_CAPTURE:
            return "pkt|:capture";


        case CommandType::PACKET_INSPECT:
            return "pkt|:inspect";


        case CommandType::NETWORK_MONITOR:
            return "net|:monitor";


        case CommandType::NETWORK_SHOW:
            return "net|:show";


        case CommandType::NETWORK_CLEAR:
            return "net|:clear";


        case CommandType::SECURITY_DETECT:
            return "sec|:detect";


        case CommandType::AI_ANALYZE:
            return "ai|:analyze";


        case CommandType::SESSION_INFO:
            return "session|:info";

        case CommandType::MAC_RESOLVE:
            return "mac|:resolve";

        case CommandType::DNS_RESOLVE:
            return "dns|:resolve";

        case CommandType::OS_FINGERPRINT:
            return "os|:fingerprint";

        case CommandType::BANNER_GRAB:
            return "banner|:grab";

        case CommandType::SUBNET_CALC:
            return "subnet|:calc";

        case CommandType::VULN_SCAN:
            return "vuln|:scan";

        case CommandType::CRED_CHECK:
            return "cred|:check";

        case CommandType::SSL_AUDIT:
            return "ssl|:audit";

        case CommandType::FIREWALL_PROBE:
            return "firewall|:probe";


        case CommandType::HELP:
            return "help";


        case CommandType::EXIT:
            return "fire";

        case CommandType::SYSTEM_INFO:
            return "system|:info";


        case CommandType::UNKNOWN:
        default:
            return "unknown";
    }
}


/*
 * ============================================================
 * CommandUtilities::requiresArgument
 * ============================================================
 */

bool CommandUtilities::requiresArgument(
    CommandType type
)
{
    switch (type)
    {
        case CommandType::HOST_FIND:
        case CommandType::PORT_SCAN:
        case CommandType::SERVICE_DETECT:
            return true;

        case CommandType::MAC_RESOLVE:
        case CommandType::DNS_RESOLVE:
        case CommandType::OS_FINGERPRINT:
        case CommandType::BANNER_GRAB:
        case CommandType::SUBNET_CALC:
            return true;

        case CommandType::SSL_AUDIT:
        case CommandType::FIREWALL_PROBE:
            return true;

        case CommandType::VULN_SCAN:
        case CommandType::CRED_CHECK:
            return false;

        case CommandType::IP_SEEK:
        case CommandType::TOPOLOGY_MAP:
        case CommandType::PACKET_CAPTURE:
        case CommandType::PACKET_INSPECT:
        case CommandType::NETWORK_MONITOR:
        case CommandType::NETWORK_SHOW:
        case CommandType::NETWORK_CLEAR:
        case CommandType::SECURITY_DETECT:
        case CommandType::AI_ANALYZE:
        case CommandType::SESSION_INFO:
        case CommandType::HELP:
        case CommandType::EXIT:
        case CommandType::UNKNOWN:
        default:
            return false;
    }
}


/*
 * ============================================================
 * CommandUtilities::printHelp
 * ============================================================
 */

void CommandUtilities::printHelp()
{
    std::cout
        << "\n"
        << "============================================================\n"
        << "                       SLIPNET HELP\n"
        << "============================================================\n\n";


    std::cout
        << "NETWORK DISCOVERY\n"
        << "------------------------------------------------------------\n"
        << "  ip|:seek\n"
        << "      Discover the local network.\n\n";


    std::cout
        << "HOST DISCOVERY\n"
        << "------------------------------------------------------------\n"
        << "  host|:find <IP>\n"
        << "      Check whether a host is available.\n\n";


    std::cout
        << "PORT SCANNING\n"
        << "------------------------------------------------------------\n"
        << "  port|:scan <IP>\n"
        << "      Scan a host for open TCP ports.\n\n";


    std::cout
        << "SERVICE DETECTION\n"
        << "------------------------------------------------------------\n"
        << "  svc|:detect <IP>\n"
        << "      Identify services running on open ports.\n\n";


    std::cout
        << "TOPOLOGY\n"
        << "------------------------------------------------------------\n"
        << "  topo|:map\n"
        << "      Build a network topology map.\n\n";


    std::cout
        << "PACKET ANALYSIS\n"
        << "------------------------------------------------------------\n"
        << "  pkt|:capture\n"
        << "      Capture network packets.\n\n"

        << "  pkt|:inspect\n"
        << "      Inspect captured packets.\n\n";


    std::cout
        << "NETWORK MONITORING\n"
        << "------------------------------------------------------------\n"
        << "  net|:monitor\n"
        << "      Monitor live network activity.\n\n"

        << "  net|:show\n"
        << "      Display collected network information.\n\n"

        << "  net|:clear\n"
        << "      Clear the current network state.\n\n";


    std::cout
        << "SECURITY\n"
        << "------------------------------------------------------------\n"
        << "  sec|:detect\n"
        << "      Analyze discovered network information for\n"
        << "      potential security risks.\n\n";


    std::cout
        << "ARTIFICIAL INTELLIGENCE\n"
        << "------------------------------------------------------------\n"
        << "  ai|:analyze\n"
        << "      Analyze network activity using AI models.\n\n";


    std::cout
        << "SESSION\n"
        << "------------------------------------------------------------\n"
        << "  session|:info\n"
        << "      Display current SlipNet session information.\n\n";


    std::cout
        << "SYSTEM\n"
        << "------------------------------------------------------------\n"
        << "  help\n"
        << "      Display this help menu.\n\n"

        << "  fire\n"
        << "      Exit SlipNet.\n\n";


    std::cout
        << "============================================================\n";
}