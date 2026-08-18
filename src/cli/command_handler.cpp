#include "cli/command_handler.hpp"

#include "cli/signal_handler.hpp"
#include "network/host_scanner.hpp"
#include "network/network_discovery.hpp"
#include "host/host_discovery.hpp"
#include "port/port_scanner.hpp"
#include "service/service_detector.hpp"
#include "topology/topology_mapper.hpp"
#include "packet/packet_capture.hpp"
#include "packet/packet_inspector.hpp"
#include "monitoring/network_monitor.hpp"
#include "security/security_detector.hpp"
#include "ai/analyzer.hpp"

#include <iostream>
#include <string>
#include <vector>

CommandHandler::CommandHandler(
    EngineContext& context
)
    : context(context)
{
}

bool CommandHandler::execute(
    const ParsedCommand& command
)
{
    switch (command.type)
    {
        case CommandType::IP_SEEK:
            handleIpSeek(command);
            break;


        case CommandType::HOST_FIND:
            handleHostFind(command);
            break;


        case CommandType::PORT_SCAN:
            handlePortScan(command);
            break;


        case CommandType::SERVICE_DETECT:
            handleServiceDetect(command);
            break;


        case CommandType::TOPOLOGY_MAP:
            handleTopologyMap(command);
            break;


        case CommandType::PACKET_CAPTURE:
            handlePacketCapture(command);
            break;


        case CommandType::PACKET_INSPECT:
            handlePacketInspect(command);
            break;


        case CommandType::NETWORK_MONITOR:
            handleNetworkMonitor(command);
            break;


        case CommandType::NETWORK_SHOW:
            handleNetworkShow(command);
            break;


        case CommandType::NETWORK_CLEAR:
            handleNetworkClear(command);
            break;


        case CommandType::SECURITY_DETECT:
            handleSecurityDetect(command);
            break;


        case CommandType::AI_ANALYZE:
            handleAIAnalyze(command);
            break;


        case CommandType::SESSION_INFO:
            handleSessionInfo(command);
            break;


        case CommandType::HELP:
            handleHelp();
            break;


        case CommandType::EXIT:
            handleExit();
            return false;


        default:
            std::cout
                << "\nUnknown command.\n"
                << "Type 'help'.\n";
            break;
    }


    return true;
}

void CommandHandler::handleHelp()
{
    std::cout << R"(

============================================================
                         SLIPNET
                   NETWORK INTELLIGENCE CLI
============================================================

DISCOVERY
------------------------------------------------------------
  ip|:seek
      Discover local interfaces and networks.

  host|:find <IP>
      Check whether a host is reachable.

  host|:find <CIDR>
      Discover reachable hosts in a subnet.


SCANNING
------------------------------------------------------------
  port|:scan <IP>
      Scan common TCP ports.

  port|:scan <IP> <start>-<end>
      Scan a custom TCP range.

  svc|:detect <IP>
      Identify services on discovered open ports.


TOPOLOGY
------------------------------------------------------------
  topo|:map
      Display discovered network topology.


PACKET ANALYSIS
------------------------------------------------------------
  pkt|:capture [interface]
      Capture passive network traffic.

  pkt|:inspect [file]
      Inspect a packet capture.


MONITORING
------------------------------------------------------------
  net|:monitor [interface]
      Monitor network activity.

  net|:show
      Display current network intelligence.

  net|:clear
      Clear collected network state.


SECURITY
------------------------------------------------------------
  sec|:detect
      Run rule-based defensive security analysis.


AI
------------------------------------------------------------
  ai|:analyze
      Analyze network features and calculate risk.


SESSION
------------------------------------------------------------
  session|:info
      Display SlipNet session information.


SYSTEM
------------------------------------------------------------
  help
      Display this help.

  fire
      Exit SlipNet.

  Ctrl+C
      Interrupt the current operation.

============================================================

)";
}

void CommandHandler::handleExit()
{
    std::cout
        << "\n"
        << "[*] Shutting down SlipNet...\n"
        << "[+] Session closed.\n";
}

void CommandHandler::handleIpSeek(
    const ParsedCommand& command
)
{
    std::cout
        << "\n[*] Starting network discovery...\n";


    NetworkDiscovery discovery(
        context.network
    );


    if (
        discovery.discover()
    )
    {
        std::cout
            << "[+] Network discovery completed.\n";
    }
    else
    {
        std::cout
            << "[!] Network discovery failed or was interrupted.\n";
    }
}


void CommandHandler::handleHostFind(
    const ParsedCommand& command
)
{
    if (command.arguments.empty())
    {
        std::cout
            << "Usage: host|:find <IP>\n";

        return;
    }


    HostScanner scanner(
        context.network
    );


    scanner.scan(
        command.arguments[0]
    );
}


void CommandHandler::handlePortScan(
    const ParsedCommand& command
)
{
    if (command.arguments.empty())
    {
        std::cout << "Usage: port|:scan <IP>\n";
        return;
    }

    std::cout << "\n";
    std::cout << "[*] Scanning host: "
              << command.arguments[0]
              << "\n";

    std::cout << "[!] Port scanning engine is being connected.\n";
}


void CommandHandler::handleServiceDetect(
    const ParsedCommand& command
)
{
    if (command.arguments.empty())
    {
        std::cout << "Usage: svc|:detect <IP>\n";
        return;
    }

    std::cout << "\n";
    std::cout << "[*] Detecting services on: "
              << command.arguments[0]
              << "\n";

    std::cout << "[!] Service detection engine is being connected.\n";
}


void CommandHandler::handleTopologyMap(
    const ParsedCommand& command
)
{
    const auto& hosts =
        context.network.getHosts();


    std::cout
        << "\n"
        << "============================================================\n"
        << "                    NETWORK TOPOLOGY\n"
        << "============================================================\n\n";


    if (hosts.empty())
    {
        std::cout
            << "[!] No hosts available.\n"
            << "[*] Run ip|:seek or host|:find first.\n";

        return;
    }


    std::cout
        << "LOCAL NODE\n"
        << "    |\n"
        << "    +---- Network\n";


    for (
        const auto& host :
        hosts
    )
    {
        std::cout
            << "           |\n"
            << "           +---- "
            << host.ip
            << " ["
            << host.status
            << "]\n";
    }


    std::cout
        << "\n============================================================\n";
}


void CommandHandler::handlePacketCapture(
    const ParsedCommand& command
)
{
    std::cout << "\n";
    std::cout << "[*] Starting packet capture...\n";
    std::cout << "[!] Packet capture engine is not connected yet.\n";
}


void CommandHandler::handlePacketInspect(
    const ParsedCommand& command
)
{
    std::cout << "\n";
    std::cout << "[*] Inspecting captured packets...\n";
    std::cout << "[!] Packet inspection engine is not connected yet.\n";
}


void CommandHandler::handleNetworkMonitor(
    const ParsedCommand& command
)
{
    std::cout << "\n";
    std::cout << "[*] Starting network monitor...\n";
    std::cout << "[!] Network monitoring engine is not connected yet.\n";
}


void CommandHandler::handleNetworkShow(
    const ParsedCommand& command
)
{
    const auto& network =
        context.network;


    std::cout
        << "\n"
        << "============================================================\n"
        << "                    SLIPNET NETWORK STATE\n"
        << "============================================================\n\n";


    std::cout
        << "HOSTS\n"
        << "------------------------------------------------------------\n";

    std::cout
        << "Discovered : "
        << network.getHostCount()
        << "\n";

    std::cout
        << "Online     : "
        << network.getOnlineHostCount()
        << "\n";


    std::cout
        << "\nSERVICES\n"
        << "------------------------------------------------------------\n";

    std::cout
        << "Detected   : "
        << network.getServices().size()
        << "\n";


    std::cout
        << "\nHOST DETAILS\n"
        << "------------------------------------------------------------\n";


    if (
        network.getHosts().empty()
    )
    {
        std::cout
            << "No hosts discovered.\n";
    }


    for (
        const auto& host :
        network.getHosts()
    )
    {
        std::cout
            << host.ip
            << "    "
            << host.status;


        if (host.online)
        {
            std::cout
                << "    "
                << host.latency_ms
                << " ms";
        }


        std::cout
            << "\n";
    }


    std::cout
        << "\n============================================================\n";
}


void CommandHandler::handleNetworkClear(
    const ParsedCommand& command
)
{
    context.network.clear();


    std::cout
        << "\n[+] Network state cleared.\n";
}


void CommandHandler::handleSecurityDetect(
    const ParsedCommand& command
)
{
    std::cout << "\n";
    std::cout << "[*] Starting security analysis...\n";
    std::cout << "[!] Security engine is not connected yet.\n";
}


void CommandHandler::handleAIAnalyze(
    const ParsedCommand& command
)
{
    std::cout << "\n";
    std::cout << "[*] Starting AI network analysis...\n";
    std::cout << "[!] AI analysis engine is not connected yet.\n";
}


void CommandHandler::handleSessionInfo(
    const ParsedCommand& command
)
{
    std::cout
        << "\n"
        << "============================================================\n"
        << "                    SLIPNET SESSION\n"
        << "============================================================\n\n";


    std::cout
        << "Version          : "
        << context.version
        << "\n";


    std::cout
        << "Hosts discovered : "
        << context.network.getHostCount()
        << "\n";


    std::cout
        << "Hosts online     : "
        << context.network.getOnlineHostCount()
        << "\n";


    std::cout
        << "Services         : "
        << context.network.getServices().size()
        << "\n";


    std::cout
        << "\nStatus           : ACTIVE\n";


    std::cout
        << "============================================================\n";
}