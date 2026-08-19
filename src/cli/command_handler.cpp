#include "cli/command_handler.hpp"
#include <iomanip>
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
#include <cstdlib>
#include <fstream>
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
  pkt|:capture
      Capture IPv4 network traffic automatically.

  pkt|:capture <interface>
      Capture traffic on a specific interface.

  pkt|:capture <interface> <seconds>
      Capture traffic for a specified duration.

  pkt|:capture <interface> <seconds> <filter>
      Filter traffic by ALL, TCP, UDP or ICMP.

  pkt|:inspect
      Inspect the most recent capture.

  pkt|:inspect <ID|file>
      Inspect an individual packet or capture file.


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
        std::cout
            << "\nUsage:\n"
            << "  port|:scan <IP>\n"
            << "  port|:scan <IP> <start>-<end>\n";

        return;
    }


    const std::string& host =
        command.arguments[0];


    std::cout
        << "\n"
        << "============================================================\n"
        << "                     PORT SCANNER\n"
        << "============================================================\n"
        << "\n"
        << "Target : "
        << host
        << "\n";


    PortScanner scanner;

    std::vector<Port> results;


    /*
     * Default scan.
     */
    if (command.arguments.size() == 1)
    {
        std::cout
            << "Mode   : Common TCP ports\n";

        results =
            scanner.scan(host);
    }


    /*
     * Custom port range.
     *
     * Example:
     *
     * port|:scan 192.168.1.10 1-1024
     */
    else
    {
        const std::string& range =
            command.arguments[1];


        const std::size_t separator =
            range.find('-');


        if (separator == std::string::npos)
        {
            std::cout
                << "\n[!] Invalid port range.\n"
                << "[*] Example: 1-1024\n";

            return;
        }


        try
        {
            const int startPort =
                std::stoi(
                    range.substr(
                        0,
                        separator
                    )
                );


            const int endPort =
                std::stoi(
                    range.substr(
                        separator + 1
                    )
                );


            if (
                startPort < 1 ||
                endPort > 65535 ||
                startPort > endPort
            )
            {
                std::cout
                    << "\n[!] Invalid port range.\n"
                    << "[*] Valid range: 1-65535\n";

                return;
            }


            std::cout
                << "Mode   : TCP "
                << startPort
                << "-"
                << endPort
                << "\n";


            results =
                scanner.scan(
                    host,
                    startPort,
                    endPort
                );
        }
        catch (...)
        {
            std::cout
                << "\n[!] Invalid port range.\n"
                << "[*] Example: 1-1024\n";

            return;
        }
    }


    /*
     * Stop cleanly if Ctrl+C was pressed.
     */
    if (
        SignalHandler::isStopRequested()
    )
    {
        std::cout
            << "\n\n[!] Port scan interrupted.\n";

        return;
    }


    int openCount = 0;


    std::cout
        << "\n"
        << "PORT       STATE       LATENCY\n"
        << "--------------------------------\n";


    for (const auto& result : results)
    {
        if (!result.open)
        {
            continue;
        }


        ++openCount;


        std::cout
            << std::left
            << std::setw(10)
            << result.number
            << std::setw(12)
            << "OPEN"
            << std::fixed
            << std::setprecision(2)
            << result.latencyMs
            << " ms\n";


        /*
         * Convert Port into PortInfo.
         *
         * PortScanner:
         *     number
         *     open
         *     latencyMs
         *
         * NetworkState:
         *     port
         *     open
         *     protocol
         *     service
         */
        PortInfo portInfo;


        portInfo.port =
            result.number;


        portInfo.open =
            result.open;


        portInfo.protocol =
            "TCP";


        /*
         * Service identification happens later
         * through svc|:detect.
         */
        portInfo.service =
            "";


        context.network.addPort(
            host,
            portInfo
        );
    }


    std::cout
        << "--------------------------------\n"
        << "Open ports : "
        << openCount
        << "\n";


    if (openCount == 0)
    {
        std::cout
            << "\n[*] No open ports found "
            << "in the scanned range.\n";
    }
    else
    {
        std::cout
            << "\n[+] Port results stored "
            << "in network state.\n";

        std::cout
            << "[*] Run "
            << "svc|:detect "
            << host
            << " to identify services.\n";
    }


    std::cout
        << "============================================================\n";
}


void CommandHandler::handleServiceDetect(
    const ParsedCommand& command
)
{
    if (command.arguments.empty())
    {
        std::cout
            << "\nUsage: svc|:detect <IP>\n";

        return;
    }


    const std::string& host =
        command.arguments[0];


    const auto& ports =
        context.network.getPorts(host);


    std::cout
        << "\n"
        << "============================================================\n"
        << "                  SERVICE DETECTION\n"
        << "============================================================\n"
        << "\n"
        << "Target : "
        << host
        << "\n";


    /*
     * Service detection depends on the
     * results of port scanning.
     */

    if (ports.empty())
    {
        std::cout
            << "\n[!] No scanned ports found for "
            << host
            << ".\n\n"
            << "[*] Run first:\n"
            << "    port|:scan "
            << host
            << "\n";

        return;
    }


    /*
     * Extract open TCP ports.
     */

    std::vector<int> openPorts;


    for (const auto& port : ports)
    {
        if (port.open)
        {
            openPorts.push_back(
                port.port
            );
        }
    }


    if (openPorts.empty())
    {
        std::cout
            << "\n[!] No open ports available "
            << "for service detection.\n";

        return;
    }


    std::cout
        << "Open ports : "
        << openPorts.size()
        << "\n\n";


    ServiceDetector detector;


    std::vector<Service> services =
        detector.detect(
            host,
            openPorts
        );


    if (
        SignalHandler::isStopRequested()
    )
    {
        std::cout
            << "\n[!] Service detection interrupted.\n";

        return;
    }


    std::cout
        << "PORT       SERVICE\n"
        << "------------------------------\n";


    int detectedCount = 0;


    for (const auto& service : services)
    {
        if (!service.detected)
        {
            continue;
        }


        ++detectedCount;


        std::cout
            << std::left
            << std::setw(10)
            << service.port
            << service.name
            << "\n";


        ServiceInfo info;

        info.ip =
            host;

        info.port =
            service.port;

        info.protocol =
            "TCP";

        info.service =
            service.name;


        context.network.addService(
            info
        );
    }


    std::cout
        << "------------------------------\n"
        << "Services detected : "
        << detectedCount
        << "\n";


    if (detectedCount == 0)
    {
        std::cout
            << "\n[*] No identifiable services "
            << "were detected.\n";
    }
    else
    {
        std::cout
            << "\n[+] Service information stored "
            << "in network state.\n";
    }


    std::cout
        << "============================================================\n";
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
    PacketCapture capture;

    std::string interfaceName;
    int seconds = 10;
    std::string filter = "ALL";


    /*
     * pkt|:capture
     *
     * Automatically choose an interface.
     */
    if (command.arguments.empty())
    {
        NetworkMonitor monitor;

        interfaceName =
            monitor.detectActiveInterface();

        if (interfaceName.empty())
        {
            std::cout
                << "\n[!] Unable to detect an active interface.\n"
                << "[*] Usage: pkt|:capture <interface> <seconds> <filter>\n";

            return;
        }
    }
    else
    {
        interfaceName =
            command.arguments[0];
    }


    /*
     * Duration.
     */
    if (command.arguments.size() >= 2)
    {
        try
        {
            seconds =
                std::stoi(
                    command.arguments[1]
                );
        }
        catch (...)
        {
            std::cout
                << "\n[!] Invalid duration.\n"
                << "[*] Example: pkt|:capture eth0 10\n";

            return;
        }

        if (
            seconds <= 0 ||
            seconds > 86400
        )
        {
            std::cout
                << "\n[!] Duration must be between 1 and 86400 seconds.\n";

            return;
        }
    }


    /*
     * Filter.
     */
    if (command.arguments.size() >= 3)
    {
        filter =
            command.arguments[2];
    }


    if (command.arguments.size() > 3)
    {
        std::cout
            << "\n[!] Too many arguments.\n"
            << "[*] Usage:\n"
            << "    pkt|:capture\n"
            << "    pkt|:capture <interface>\n"
            << "    pkt|:capture <interface> <seconds>\n"
            << "    pkt|:capture <interface> <seconds> <filter>\n";

        return;
    }


    std::vector<Packet> packets =
        capture.capture(
            interfaceName,
            seconds,
            filter
        );

    (void)packets;
}


void CommandHandler::handlePacketInspect(
    const ParsedCommand& command
)
{
    PacketInspector inspector;

    const std::string captureFile =
        "data/last_capture.txt";


    /*
     * pkt|:inspect
     */
    if (command.arguments.empty())
    {
        inspector.inspectFile(
            captureFile
        );

        return;
    }


    /*
     * pkt|:inspect <ID>
     */
    if (command.arguments.size() == 1)
    {
        try
        {
            const uint64_t packetId =
                std::stoull(
                    command.arguments[0]
                );

            if (packetId == 0)
            {
                std::cout
                    << "\n[!] Packet ID must be greater than zero.\n";

                return;
            }

            inspector.inspectFile(
                captureFile,
                packetId
            );
        }
        catch (...)
        {
            std::cout
                << "\n[!] Invalid packet ID.\n"
                << "[*] Example: pkt|:inspect 1\n";
        }

        return;
    }


    std::cout
        << "\n[!] Too many arguments.\n"
        << "[*] Usage:\n"
        << "    pkt|:inspect\n"
        << "    pkt|:inspect <ID>\n";
}


void CommandHandler::handleNetworkMonitor(
    const ParsedCommand& command
)
{
    std::string interfaceName;

    int seconds = 0;


    /*
     * --------------------------------------------------------
     * Determine interface
     * --------------------------------------------------------
     *
     * No argument:
     *
     *     net|:monitor
     *
     * Automatically detect active interface.
     *
     * With argument:
     *
     *     net|:monitor eth1
     *
     * Use the specified interface.
     */

    NetworkMonitor monitor;


    if (command.arguments.empty())
    {
        std::cout
            << "\n[*] Detecting active network interface...\n";


        interfaceName =
            monitor.detectActiveInterface();


        if (interfaceName.empty())
        {
            std::cout
                << "[!] No active network interface found.\n";

            return;
        }


        std::cout
            << "[+] Active interface: "
            << interfaceName
            << "\n";
    }
    else
    {
        interfaceName =
            command.arguments[0];
    }


    /*
     * --------------------------------------------------------
     * Optional duration
     * --------------------------------------------------------
     *
     * net|:monitor
     * net|:monitor eth1
     * net|:monitor eth1 30
     */

    if (
        command.arguments.size() >= 2
    )
    {
        try
        {
            seconds =
                std::stoi(
                    command.arguments[1]
                );


            if (seconds < 0)
            {
                std::cout
                    << "[!] Duration cannot be negative.\n";

                return;
            }
        }
        catch (...)
        {
            std::cout
                << "[!] Invalid duration.\n"
                << "[*] Example:\n"
                << "    net|:monitor eth1 30\n";

            return;
        }
    }


    /*
     * Reject unnecessary arguments.
     */

    if (
        command.arguments.size() > 2
    )
    {
        std::cout
            << "\nUsage:\n"
            << "  net|:monitor\n"
            << "  net|:monitor <interface>\n"
            << "  net|:monitor <interface> <seconds>\n";

        return;
    }


    /*
     * --------------------------------------------------------
     * Start monitoring
     * --------------------------------------------------------
     */

    SignalHandler::clearStop();


    monitor.monitor(
        interfaceName,
        seconds
    );


    SignalHandler::clearStop();
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