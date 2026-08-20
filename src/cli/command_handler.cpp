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
#include <cctype>
#include <cstdint>

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
            << "[!] Usage: port|:scan <IP> [start-end]\n";
        return;
    }

    const std::string& host =
        command.arguments[0];

    int startPort = 0;
    int endPort = 0;

    PortScanner scanner;

    std::vector<Port> results;

    if (command.arguments.size() == 1)
    {
        std::cout
            << "\n[*] Scanning common TCP ports on "
            << host
            << "...\n";

        results = scanner.scan(host);
    }
    else
    {
        const std::string range =
            command.arguments[1];

        const std::size_t separator =
            range.find('-');

        if (separator == std::string::npos)
        {
            std::cout
                << "[!] Invalid port range.\n"
                << "    Example: port|:scan "
                << host
                << " 1-1024\n";
            return;
        }

        try
        {
            startPort =
                std::stoi(
                    range.substr(0, separator)
                );

            endPort =
                std::stoi(
                    range.substr(separator + 1)
                );
        }
        catch (...)
        {
            std::cout
                << "[!] Invalid port range.\n";
            return;
        }

        if (
            startPort < 1 ||
            endPort > 65535 ||
            startPort > endPort
        )
        {
            std::cout
                << "[!] Port range must be "
                << "1-65535 and start <= end.\n";
            return;
        }

        std::cout
            << "\n[*] Scanning "
            << host
            << " ports "
            << startPort
            << "-"
            << endPort
            << "...\n";

        results =
            scanner.scan(
                host,
                startPort,
                endPort
            );
    }

    int openCount = 0;

    std::cout
        << "\nPORT       STATE       LATENCY\n"
        << "--------------------------------------\n";

    for (const auto& result : results)
    {
        PortInfo info;

        info.port = result.number;
        info.open = result.open;
        info.protocol = "TCP";
        info.service = "";

        context.network.addPort(
            host,
            info
        );

        if (!result.open)
        {
            continue;
        }

        ++openCount;

        std::cout
            << result.number
            << "        OPEN        "
            << std::fixed
            << std::setprecision(2)
            << result.latencyMs
            << " ms\n";
    }

    std::cout
        << "--------------------------------------\n";

    std::cout
        << "[+] Scan completed.\n"
        << "[+] Open ports: "
        << openCount
        << "\n";
}


void CommandHandler::handleServiceDetect(
    const ParsedCommand& command
)
{
    if (command.arguments.empty())
    {
        std::cout
            << "[!] Usage: svc|:detect <IP>\n";
        return;
    }

    const std::string& host =
        command.arguments[0];

    const auto& storedPorts =
        context.network.getPorts(host);

    if (storedPorts.empty())
    {
        std::cout
            << "[!] No port scan data for "
            << host
            << ".\n";

        std::cout
            << "[*] Run:\n"
            << "    port|:scan "
            << host
            << "\n";

        return;
    }

    std::vector<int> openPorts;

    for (const auto& port : storedPorts)
    {
        if (port.open)
        {
            openPorts.push_back(port.port);
        }
    }

    if (openPorts.empty())
    {
        std::cout
            << "[!] No open ports found for "
            << host
            << ".\n";
        return;
    }

    std::cout
        << "\n[*] Detecting services on "
        << host
        << "...\n";

    ServiceDetector detector;

    const auto services =
        detector.detect(
            host,
            openPorts
        );

    std::cout
        << "\nPORT       SERVICE       VERSION\n"
        << "---------------------------------------------\n";

    for (const auto& service : services)
    {
        ServiceInfo info;

        info.ip = host;
        info.port = service.port;
        info.protocol = service.protocol;
        info.service = service.name;
        info.version = service.version;

        context.network.addService(info);

        std::cout
            << std::left
            << std::setw(11)
            << service.port
            << std::setw(14)
            << service.name
            << service.version
            << '\n';
    }

    std::cout
        << "---------------------------------------------\n";

    std::cout
        << "[+] Service detection completed.\n"
        << "[+] Services detected: "
        << services.size()
        << "\n";
}


void CommandHandler::handleTopologyMap(
    const ParsedCommand&
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
            << "[!] No network information available.\n"
            << "[*] Run ip|:seek or host|:find first.\n\n"
            << "============================================================\n";

        return;
    }

    /*
     * Try to determine the local address and default gateway.
     */
    std::string localIP;
    std::string gateway;

    {
        FILE* pipe =
            popen(
                "ip route get 1.1.1.1 2>/dev/null",
                "r"
            );

        if (pipe)
        {
            char buffer[512];

            std::string output;

            while (
                fgets(
                    buffer,
                    sizeof(buffer),
                    pipe
                )
            )
            {
                output += buffer;
            }

            pclose(pipe);

            /*
             * Extract local source address.
             */
            std::size_t srcPos =
                output.find("src ");

            if (srcPos != std::string::npos)
            {
                srcPos += 4;

                std::size_t end =
                    output.find(
                        ' ',
                        srcPos
                    );

                if (end == std::string::npos)
                {
                    end = output.size();
                }

                localIP =
                    output.substr(
                        srcPos,
                        end - srcPos
                    );
            }

            /*
             * Extract gateway.
             */
            std::size_t viaPos =
                output.find(" via ");

            if (viaPos != std::string::npos)
            {
                viaPos += 5;

                std::size_t end =
                    output.find(
                        ' ',
                        viaPos
                    );

                if (end == std::string::npos)
                {
                    end = output.size();
                }

                gateway =
                    output.substr(
                        viaPos,
                        end - viaPos
                    );
            }
        }
    }

    std::cout
        << "LOCAL SYSTEM\n"
        << "------------------------------------------------------------\n";

    if (!localIP.empty())
    {
        std::cout
            << "  Local IP : "
            << localIP
            << "\n";
    }
    else
    {
        std::cout
            << "  Local IP : unknown\n";
    }

    if (!gateway.empty())
    {
        std::cout
            << "  Gateway  : "
            << gateway
            << "\n";
    }
    else
    {
        std::cout
            << "  Gateway  : not detected\n";
    }

    std::cout
        << "\nNETWORK GRAPH\n"
        << "------------------------------------------------------------\n";

    /*
     * Local node.
     */
    std::cout
        << "\n  [LOCAL] "
        << (
            localIP.empty()
                ? "this-host"
                : localIP
        )
        << "\n";

    /*
     * Gateway node.
     */
    if (!gateway.empty())
    {
        std::cout
            << "      |\n"
            << "      +---- [GATEWAY] "
            << gateway
            << "\n";
    }

    /*
     * Discovered hosts.
     */
    for (std::size_t i = 0;
         i < hosts.size();
         ++i)
    {
        const auto& host =
            hosts[i];

        const bool last =
            (i + 1 == hosts.size());

        std::cout
            << "      "
            << (last ? "    " : "|   ")
            << "\n"
            << "      "
            << (last ? "`---- " : "+---- ")
            << "[HOST] "
            << host.ip
            << " ["
            << host.status
            << "]";

        if (host.latency_ms > 0.0)
        {
            std::cout
                << " "
                << std::fixed
                << std::setprecision(2)
                << host.latency_ms
                << " ms";
        }

        std::cout
            << "\n";

        const auto& ports =
            context.network.getPorts(
                host.ip
            );

        int openPorts = 0;

        for (const auto& port : ports)
        {
            if (port.open)
            {
                ++openPorts;
            }
        }

        if (openPorts > 0)
        {
            std::cout
                << "      "
                << (last ? "     " : "|    ")
                << "    Open TCP ports: "
                << openPorts
                << "\n";
        }
    }

    std::cout
        << "\nLEGEND\n"
        << "------------------------------------------------------------\n"
        << "  [LOCAL]   SlipNet host\n"
        << "  [GATEWAY] Default network gateway\n"
        << "  [HOST]    Host discovered by SlipNet\n";

    std::cout
        << "\n"
        << "[+] Topology generated from current discovery state.\n"
        << "[+] Hosts discovered: "
        << hosts.size()
        << "\n";

    std::cout
        << "============================================================\n";
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
     * Automatically detect interface.
     */
    if (command.arguments.empty())
    {
        NetworkMonitor monitor;

        interfaceName =
            monitor.detectActiveInterface();

        if (interfaceName.empty())
        {
            std::cout
                << "\n[!] Unable to detect an active interface.\n";

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
                << "[*] Example:\n"
                << "    pkt|:capture eth1 10\n";

            return;
        }

        if (
            seconds <= 0 ||
            seconds > 86400
        )
        {
            std::cout
                << "\n[!] Duration must be between "
                << "1 and 86400 seconds.\n";

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

    /*
     * Too many arguments.
     */
    if (command.arguments.size() > 3)
    {
        std::cout
            << "\n[!] Too many arguments.\n"
            << "\nUsage:\n"
            << "  pkt|:capture\n"
            << "  pkt|:capture <interface>\n"
            << "  pkt|:capture <interface> <seconds>\n"
            << "  pkt|:capture <interface> <seconds> <filter>\n";

        return;
    }

    std::cout
        << "\n[*] Starting packet capture...\n"
        << "[+] Interface : "
        << interfaceName
        << "\n"
        << "[+] Duration  : "
        << seconds
        << " seconds\n"
        << "[+] Filter    : "
        << filter
        << "\n";

    SignalHandler::clearStop();

    const auto packets =
        capture.capture(
            interfaceName,
            seconds,
            filter
        );

    SignalHandler::clearStop();

    std::cout
        << "\n============================================================\n"
        << "                    CAPTURE SUMMARY\n"
        << "============================================================\n";

    std::cout
        << "Interface       : "
        << interfaceName
        << "\n";

    std::cout
        << "Duration        : "
        << seconds
        << " seconds\n";

    std::cout
        << "Filter          : "
        << filter
        << "\n";

    std::cout
        << "Packets captured: "
        << packets.size()
        << "\n";

    std::uint64_t totalBytes = 0;

    for (const auto& packet : packets)
    {
        totalBytes +=
            static_cast<std::uint64_t>(
                packet.length
            );
    }

    std::cout
        << "Total bytes     : "
        << totalBytes
        << "\n";

    if (packets.empty())
    {
        std::cout
            << "\n[!] No packets were captured.\n"
            << "[*] This can happen when the interface is idle.\n";
    }
    else
    {
        std::cout
            << "\n[+] Packet capture completed.\n"
            << "[+] Capture saved to:\n"
            << "    data/last_capture.txt\n";
    }

    std::cout
        << "============================================================\n";
}


void CommandHandler::handlePacketInspect(
    const ParsedCommand& command
)
{
    PacketInspector inspector;

    const std::string defaultFile =
        "data/last_capture.txt";

    /*
     * No argument:
     *
     * Inspect the most recent capture.
     */
    if (command.arguments.empty())
    {
        std::cout
            << "\n[*] Inspecting latest capture...\n";

        inspector.inspectFile(
            defaultFile
        );

        return;
    }

    /*
     * More than one argument is invalid.
     */
    if (command.arguments.size() > 1)
    {
        std::cout
            << "\n[!] Too many arguments.\n"
            << "\nUsage:\n"
            << "  pkt|:inspect\n"
            << "  pkt|:inspect <ID>\n"
            << "  pkt|:inspect <file>\n";

        return;
    }

    const std::string argument =
        command.arguments[0];

    /*
     * Determine whether the argument is a packet ID.
     */
    bool numeric = !argument.empty();

    for (char c : argument)
    {
        if (!std::isdigit(
                static_cast<unsigned char>(c)
            ))
        {
            numeric = false;
            break;
        }
    }

    if (numeric)
    {
        try
        {
            const std::uint64_t packetId =
                std::stoull(argument);

            if (packetId == 0)
            {
                std::cout
                    << "\n[!] Packet ID must be greater than zero.\n";

                return;
            }

            std::cout
                << "\n[*] Inspecting packet #"
                << packetId
                << "...\n";

            inspector.inspectFile(
                defaultFile,
                packetId
            );
        }
        catch (...)
        {
            std::cout
                << "\n[!] Invalid packet ID.\n";
        }

        return;
    }

    /*
     * Otherwise treat it as a capture filename.
     */
    std::cout
        << "\n[*] Inspecting capture file:\n"
        << "    "
        << argument
        << "\n";

    inspector.inspectFile(
        argument
    );
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
    const ParsedCommand&
)
{
    const auto& hosts =
        context.network.getHosts();

    const auto& services =
        context.network.getServices();

    std::cout
        << "\n"
        << "============================================================\n"
        << "                    NETWORK STATE\n"
        << "============================================================\n";

    std::cout
        << "Hosts discovered : "
        << context.network.getHostCount()
        << '\n';

    std::cout
        << "Hosts online     : "
        << context.network.getOnlineHostCount()
        << '\n';

    std::cout
        << "Services         : "
        << services.size()
        << '\n';

    std::cout
        << "\nHOSTS\n"
        << "------------------------------------------------------------\n";

    if (hosts.empty())
    {
        std::cout << "No hosts discovered.\n";
    }
    else
    {
        for (const auto& host : hosts)
        {
            std::cout
                << host.ip
                << "  "
                << host.status
                << "  "
                << std::fixed
                << std::setprecision(2)
                << host.latency_ms
                << " ms\n";

            const auto& ports =
                context.network.getPorts(host.ip);

            for (const auto& port : ports)
            {
                if (!port.open)
                {
                    continue;
                }

                std::cout
                    << "    "
                    << port.port
                    << "/"
                    << port.protocol;

                if (!port.service.empty())
                {
                    std::cout
                        << "  "
                        << port.service;
                }

                std::cout << '\n';
            }
        }
    }

    std::cout
        << "\nSERVICES\n"
        << "------------------------------------------------------------\n";

    if (services.empty())
    {
        std::cout << "No services detected.\n";
    }
    else
    {
        for (const auto& service : services)
        {
            std::cout
                << service.ip
                << "  "
                << service.port
                << "/"
                << service.protocol
                << "  "
                << service.service;

            if (!service.version.empty())
            {
                std::cout
                    << "  "
                    << service.version;
            }

            std::cout << '\n';
        }
    }

    std::cout
        << "============================================================\n";
}


void CommandHandler::handleNetworkClear(
    const ParsedCommand&
)
{
    context.network.clear();

    std::cout
        << "\n"
        << "[+] Network state cleared.\n"
        << "[+] Hosts, ports and services removed.\n";
}


void CommandHandler::handleSecurityDetect(
    const ParsedCommand&
)
{
    const auto& hosts =
        context.network.getHosts();

    std::cout
        << "\n"
        << "============================================================\n"
        << "                 SLIPNET SECURITY ANALYSIS\n"
        << "============================================================\n";

    if (hosts.empty())
    {
        std::cout
            << "\n[!] No discovered hosts available.\n"
            << "\n[*] Security analysis uses information already\n"
            << "    collected by SlipNet.\n"
            << "\n[*] Run:\n"
            << "    ip|:seek\n"
            << "    port|:scan <IP>\n"
            << "    svc|:detect <IP>\n"
            << "\n"
            << "============================================================\n";

        return;
    }

    SecurityDetector detector;

    std::size_t totalAlerts = 0;

    std::size_t highAlerts = 0;

    std::size_t mediumAlerts = 0;

    std::size_t lowAlerts = 0;

    std::size_t infoAlerts = 0;

    for (const auto& host : hosts)
    {
        const auto& ports =
            context.network.getPorts(
                host.ip
            );

        /*
         * Collect services belonging to
         * this particular host.
         */
        std::vector<ServiceInfo> hostServices;

        for (
            const auto& service :
            context.network.getServices()
        )
        {
            if (service.ip == host.ip)
            {
                hostServices.push_back(
                    service
                );
            }
        }

        /*
         * Analyze only information already
         * discovered by SlipNet.
         */
        const auto alerts =
            detector.analyze(
                host.ip,
                ports,
                hostServices
            );

        std::cout
            << "\nHOST: "
            << host.ip
            << "\n"
            << "------------------------------------------------------------\n";

        int openPorts = 0;

        for (const auto& port : ports)
        {
            if (port.open)
            {
                ++openPorts;
            }
        }

        std::cout
            << "Status       : "
            << host.status
            << "\n"
            << "Open ports   : "
            << openPorts
            << "\n"
            << "Services     : "
            << hostServices.size()
            << "\n"
            << "Alerts       : "
            << alerts.size()
            << "\n";

        if (alerts.empty())
        {
            std::cout
                << "\n[+] No rule-based security findings.\n";

            continue;
        }

        std::cout
            << "\nFINDINGS\n"
            << "------------------------------------------------------------\n";

        for (const auto& alert : alerts)
        {
            std::string severity;

            switch (alert.severity)
            {
                case 3:
                    severity = "HIGH";
                    ++highAlerts;
                    break;

                case 2:
                    severity = "MEDIUM";
                    ++mediumAlerts;
                    break;

                case 1:
                    severity = "LOW";
                    ++lowAlerts;
                    break;

                default:
                    severity = "INFO";
                    ++infoAlerts;
                    break;
            }

            ++totalAlerts;

            std::cout
                << "["
                << severity
                << "] "
                << alert.type
                << "\n"
                << "    "
                << alert.description
                << "\n";
        }
    }

    std::cout
        << "\n"
        << "============================================================\n"
        << "                 SECURITY SUMMARY\n"
        << "============================================================\n";

    std::cout
        << "Hosts analyzed : "
        << hosts.size()
        << "\n"
        << "Total findings : "
        << totalAlerts
        << "\n"
        << "High           : "
        << highAlerts
        << "\n"
        << "Medium         : "
        << mediumAlerts
        << "\n"
        << "Low            : "
        << lowAlerts
        << "\n"
        << "Informational  : "
        << infoAlerts
        << "\n";

    if (totalAlerts == 0)
    {
        std::cout
            << "\n[+] No rule-based security findings detected.\n";
    }
    else
    {
        std::cout
            << "\n[!] Security findings require review.\n"
            << "[*] These findings are based on discovered\n"
            << "    network exposure and are not proof of compromise.\n";
    }

    std::cout
        << "============================================================\n";
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
    const ParsedCommand&
)
{
    std::size_t portCount = 0;

    for (const auto& host :
         context.network.getHosts())
    {
        portCount +=
            context.network
                .getPorts(host.ip)
                .size();
    }

    std::cout
        << "\n"
        << "============================================================\n"
        << "                    SESSION INFORMATION\n"
        << "============================================================\n";

    std::cout
        << "SlipNet version : "
        << context.version
        << '\n';

    std::cout
        << "Running         : "
        << (context.running ? "YES" : "NO")
        << '\n';

    std::cout
        << "Hosts           : "
        << context.network.getHostCount()
        << '\n';

    std::cout
        << "Online hosts    : "
        << context.network.getOnlineHostCount()
        << '\n';

    std::cout
        << "Stored ports    : "
        << portCount
        << '\n';

    std::cout
        << "Services        : "
        << context.network.getServices().size()
        << '\n';

    std::cout
        << "============================================================\n";
}