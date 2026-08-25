#include "cli/command_handler.hpp"
#include <iomanip>
#include "cli/signal_handler.hpp"
#include "network/host_scanner.hpp"
#include "network/network_discovery.hpp"
#include "host/host_discovery.hpp"
#include "port/port_scanner.hpp"
#include "service/service_detector.hpp"
#include "topology/topology_mapper.hpp"
#include "platform/network.hpp"
#include "packet/packet_capture.hpp"
#include "packet/packet_inspector.hpp"
#include "monitoring/network_monitor.hpp"
#include "security/security_detector.hpp"
#include "platform/route.hpp"
#include "platform/topology.hpp"
#include "platform/session.hpp"
#include "ai/analyzer.hpp"
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdint>
#include "network/mac_resolver.hpp"
#include "network/dns_resolver.hpp"
#include "network/os_fingerprint.hpp"
#include "network/banner_grabber.hpp"
#include "network/subnet_calculator.hpp"
#include "system/system_info.hpp"
#include "security/vulnerability_scanner.hpp"
#include "security/credential_checker.hpp"
#include "security/ssl_auditor.hpp"
#include "security/firewall_probe.hpp"

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

        case CommandType::MAC_RESOLVE:
            handleMacResolve(command);
            break;

        case CommandType::DNS_RESOLVE:
            handleDnsResolve(command);
            break;

        case CommandType::OS_FINGERPRINT:
            handleOSFingerprint(command);
            break;

        case CommandType::BANNER_GRAB:
            handleBannerGrab(command);
            break;

        case CommandType::SUBNET_CALC:
            handleSubnetCalc(command);
            break;

        case CommandType::VULN_SCAN:
            handleVulnScan(command);
            break;

        case CommandType::CRED_CHECK:
            handleCredCheck(command);
            break;

        case CommandType::SSL_AUDIT:
            handleSSLAudit(command);
            break;

        case CommandType::FIREWALL_PROBE:
            handleFirewallProbe(command);
            break;

        case CommandType::SYSTEM_INFO:
        handleSystemInfo(command);
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
  port|:scan <IP> <start-port> <end-port>
      Scan common TCP ports.

  port|:scan <IP> <start>-<end>
      Scan a custom TCP range.

  svc|:detect <IP>
      Identify services on discovered open ports.


TOPOLOGY
------------------------------------------------------------
  topo|:map
      Display discovered network topology.

INTELLIGENCE
------------------------------------------------------------
  mac|:resolve <IP>
      Resolve MAC address, interface and vendor.

  dns|:resolve <hostname|IP>
      Resolve DNS records or perform reverse lookup.

  os|:fingerprint <IP>
      Perform heuristic operating-system fingerprinting.

  banner|:grab <IP> <PORT>
      Retrieve a service/application banner.

  subnet|:calc <CIDR>
      Calculate network, broadcast, hosts and masks.

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
      Run defensive security analysis on discovered hosts.

  vuln|:scan
      Analyze all detected services for security exposure.

  vuln|:scan <IP>
      Analyze detected services on one host.

  cred|:check
      Audit discovered services for credential exposure risks.

  cred|:check <IP>
      Audit credential exposure for one host.

  ssl|:audit <HOST[:PORT]>
  ssl|:audit <dname>
      Perform a TLS certificate and protocol audit.

  firewall|:probe
  firewall|:probe <IP>
  firewall|:probe <IP> <PORT>
      Analyze observed port states and firewall indicators.
      
  SECURITY NOTES
------------------------------------------------------------
  SlipNet performs defensive network analysis.

  Security findings are indicators and should be verified.

  SlipNet does not perform:
      - password guessing
      - credential brute force
      - exploitation
      - destructive testing

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

  system|:info       
      Display local system information

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

    const bool success =
        discovery.discover();

    if (!success)
    {
        std::cout
            << "[!] Network discovery failed or was interrupted.\n";
    }
}


void CommandHandler::handleHostFind(
    const ParsedCommand& command
)
{
    if (command.arguments.size() != 1)
    {
        std::cout
            << "\n"
            << "Usage: host|:find <IP>\n"
            << "\n"
            << "Examples:\n"
            << "  host|:find 192.168.1.10\n"
            << "  host|:find 10.108.155.140\n"
            << "\n"
            << "Use ip|:seek for network discovery.\n";

        return;
    }


    const std::string& target =
        command.arguments[0];


    std::cout
        << "\n"
        << "[*] Checking host: "
        << target
        << "\n";


    /*
     * --------------------------------------------------------
     * CIDR validation
     * --------------------------------------------------------
     *
     * host|:find is intentionally a single-host operation.
     *
     * Network ranges belong to:
     *
     *     ip|:seek
     *
     * Therefore we reject CIDR notation here instead of
     * incorrectly reporting the entire network as offline.
     */

    if (
        target.find('/') !=
        std::string::npos
    )
    {
        std::cout
            << "\n"
            << "[!] Invalid host target.\n"
            << "[*] CIDR notation is not valid for host lookup.\n"
            << "[*] Use ip|:seek for network discovery.\n";

        return;
    }


    /*
     * --------------------------------------------------------
     * Host discovery
     * --------------------------------------------------------
     */

    HostDiscovery discovery;

    const Host host =
        discovery.check(
            target
        );


    /*
     * --------------------------------------------------------
     * Result
     * --------------------------------------------------------
     */

    if (host.reachable)
    {
        std::cout
            << "[+] Host is ONLINE\n"
            << "[+] Latency: "
            << std::fixed
            << std::setprecision(2)
            << host.latencyMs
            << " ms\n";
    }
    else
    {
        std::cout
            << "[-] Host is OFFLINE\n"
            << "[*] No response was received from the target.\n";
    }
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

    // --------- Require discovered network information.---------
    if (hosts.empty())
    {
        std::cout
            << "\n"
            << "[!] No discovered hosts available.\n"
            << "\n"
            << "[*] Run:\n"
            << "    ip|:seek\n"
            << "\n"
            << "[*] Then run:\n"
            << "    topo|:map\n"
            << "\n";

        return;
    }


    // -------------- Create topology mapper.------------
    TopologyMapper mapper;


    // -------Get local network interfaces.----------
     
    // This is platform independent:
    // Linux   -> network_linux.cpp
    // Windows -> network_windows.cpp

    const auto interfaces =
        slipnet::platform::getNetworkInterfaces();


    //-------- Get local topology information.---------
     
    // Linux   -> topology_linux.cpp
    // Windows -> topology_windows.cpp


    const auto topologyInfo =
        slipnet::platform::getLocalTopologyInfo();

    std::string localIP =
        topologyInfo.localAddress;

    const std::string gatewayIP =
        topologyInfo.gatewayAddress;


    //--------- Add active local interfaces.---------
    for (const auto& interface : interfaces)
    {
        if (!interface.up)
        {
            continue;
        }

        if (interface.ipv4Address.empty())
        {
            continue;
        }

        // Remember the primary local IPv4 address.
        if (localIP.empty())
        {
            localIP = interface.ipv4Address;
        }

        Node node;

        node.name =
            interface.name;

        node.address =
            interface.ipv4Address;

        node.type =
            "LOCAL";

        mapper.addNode(node);
    }


    //----------- Add discovered hosts.----------------
    for (const auto& host : hosts)
    {
        if (!host.online)
        {
            continue;
        }

        // Do not duplicate the local machine as a HOST node.
        if (
            !localIP.empty() &&
            host.ip == localIP
        )
        {
            continue;
        }

        // Gateway gets a special topology role.
        const bool isGateway =
            !gatewayIP.empty() &&
            host.ip == gatewayIP;

        Node node;

        node.name =
            isGateway
                ? "gateway"
                : host.ip;

        node.address =
            host.ip;

        node.type =
            isGateway
                ? "GATEWAY"
                : "HOST";

        mapper.addNode(node);
    }

    // Connect local machine to gateway.
    // This relationship is supported by actual routing
    // information, so it is safe to represent.
    if (
        !localIP.empty() &&
        !gatewayIP.empty()
    )
    {
        Edge edge;

        edge.from =
            localIP;

        edge.to =
            gatewayIP;

        mapper.addEdge(edge);
    }

    // Connect local machine to discovered hosts.
    // These are logical relationships, NOT claims about
    // physical switches or routers.
    if (!localIP.empty())
    {
        for (const auto& host : hosts)
        {
            if (!host.online)
            {
                continue;
            }

            if (host.ip == localIP)
            {
                continue;
            }

            // Avoid adding the gateway twice.
            if (
                !gatewayIP.empty() &&
                host.ip == gatewayIP
            )
            {
                continue;
            }

            Edge edge;

            edge.from =
                localIP;

            edge.to =
                host.ip;

            mapper.addEdge(edge);
        }
    }


    // Display topology.


    mapper.display();

    std::cout
        << "\n"
        << "[+] Topology mapping completed successfully.\n";
}


void CommandHandler::handlePacketCapture(
    const ParsedCommand& command
)
{
    std::string interfaceName;

    int seconds = 10;

    std::string filter = "ALL";


    //------------ Arguments-----------------
    // pkt|:capture
    // pkt|:capture <interface>
    // pkt|:capture <interface> <seconds>
    // pkt|:capture <interface> <seconds> <filter>

    if (command.arguments.size() > 3)
    {
        std::cout
            << "\n[!] Too many arguments.\n"
            << "\nUsage:\n"
            << "  pkt|:capture\n"
            << "  pkt|:capture <interface>\n"
            << "  pkt|:capture <interface> <seconds>\n"
            << "  pkt|:capture <interface> <seconds> <filter>\n"
            << "\nFilters:\n"
            << "  ALL\n"
            << "  TCP\n"
            << "  UDP\n"
            << "  ICMP\n";

        return;
    }

    // -------------- Interface------------
    if (command.arguments.empty())
    {
        slipnet::monitoring::NetworkMonitor monitor;

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

    // ----------------Duration----------------
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
                << "[*] Duration must be an integer.\n"
                << "[*] Example:\n"
                << "    pkt|:capture eth1 10\n";

            return;
        }
    }

    if (
        seconds < 1 ||
        seconds > 86400
    )
    {
        std::cout
            << "\n[!] Duration must be between "
            << "1 and 86400 seconds.\n";

        return;
    }

    // ----------------Filter--------------
    if (command.arguments.size() >= 3)
    {
        filter =
            command.arguments[2];
    }

    std::transform(
        filter.begin(),
        filter.end(),
        filter.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                std::toupper(c)
            );
        }
    );


    if (
        filter != "ALL" &&
        filter != "TCP" &&
        filter != "UDP" &&
        filter != "ICMP"
    )
    {
        std::cout
            << "\n[!] Unsupported filter: "
            << filter
            << '\n'
            << "[*] Supported filters: "
            << "ALL, TCP, UDP, ICMP\n";

        return;
    }

    //--------------------- Start capture-----------------
    std::cout
        << "\n============================================================\n"
        << "                    PACKET CAPTURE\n"
        << "============================================================\n"
        << "\n"
        << "  Interface : "
        << interfaceName
        << "\n"
        << "  Duration  : "
        << seconds
        << " seconds\n"
        << "  Filter    : "
        << filter
        << "\n"
        << "\n"
        << "[*] Press Ctrl+C to stop the capture early.\n";


    PacketCapture capture;

    SignalHandler::clearStop();


    const auto packets =
        capture.capture(
            interfaceName,
            seconds,
            filter
        );


    SignalHandler::clearStop();

    //----------------- Summary--------------------
    std::uint64_t totalBytes = 0;
    std::size_t tcpCount = 0;
    std::size_t udpCount = 0;
    std::size_t icmpCount = 0;
    std::size_t otherCount = 0;

    for (const auto& packet : packets)
    {
        totalBytes +=
            static_cast<std::uint64_t>(
                packet.length
            );

        if (packet.protocol == "TCP")
        {
            ++tcpCount;
        }
        else if (packet.protocol == "UDP")
        {
            ++udpCount;
        }
        else if (packet.protocol == "ICMP")
        {
            ++icmpCount;
        }
        else
        {
            ++otherCount;
        }
    }


    std::cout
        << "\n"
        << "------------------------------------------------------------\n"
        << " Capture Statistics\n"
        << "------------------------------------------------------------\n"
        << "  Total packets : "
        << packets.size()
        << '\n'
        << "  Total bytes   : "
        << totalBytes
        << '\n'
        << "  TCP           : "
        << tcpCount
        << '\n'
        << "  UDP           : "
        << udpCount
        << '\n'
        << "  ICMP          : "
        << icmpCount
        << '\n'
        << "  Other         : "
        << otherCount
        << '\n'
        << "------------------------------------------------------------\n";

    if (packets.empty())
    {
        std::cout
            << "\n[!] No matching IPv4 packets captured.\n";
    }
    else
    {
        std::cout
            << "\n[+] Packet capture completed successfully.\n";
    }
}


void CommandHandler::handlePacketInspect(
    const ParsedCommand& command
)
{
    PacketInspector inspector;

    const std::string defaultFile =
        "data/last_capture.txt";

    // No argument:
    // Inspect the most recent capture.
    if (command.arguments.empty())
    {
        std::cout
            << "\n[*] Inspecting latest capture...\n";

        inspector.inspectFile(
            defaultFile
        );

        return;
    }

    // More than one argument is invalid.
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

    // Determine whether the argument is a packet ID.
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

    // Otherwise treat it as a capture filename.
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
    slipnet::monitoring::NetworkMonitor monitor;

    //  --------Supported:------------
    
    // net|:monitor
    // net|:monitor <interface>
    // net|:monitor <interface> <interval>
    if (command.arguments.size() > 2)
    {
        std::cout
            << "\n[!] Too many arguments.\n"
            << "\nUsage:\n"
            << "  net|:monitor\n"
            << "  net|:monitor <interface>\n"
            << "  net|:monitor <interface> <interval>\n";

        return;
    }

    //---------------- Interface--------------------
    std::string interfaceName;

    if (command.arguments.empty())
    {
        interfaceName =
            monitor.detectActiveInterface();

        if (interfaceName.empty())
        {
            std::cout
                << "\n[!] Unable to detect an active network interface.\n";

            return;
        }
    }
    else
    {
        interfaceName =
            command.arguments[0];

        if (interfaceName.empty())
        {
            std::cout
                << "\n[!] Network interface cannot be empty.\n";

            return;
        }
    }

    //--------------------- Sampling interval-------------------
    int intervalSeconds = 1;

    if (command.arguments.size() == 2)
    {
        try
        {
            std::size_t processed = 0;

            intervalSeconds =
                std::stoi(
                    command.arguments[1],
                    &processed
                );

            if (
                processed !=
                command.arguments[1].size()
            )
            {
                throw std::invalid_argument(
                    "invalid interval"
                );
            }
        }
        catch (...)
        {
            std::cout
                << "\n[!] Invalid monitoring interval.\n"
                << "[!] Interval must be a whole number of seconds.\n";

            return;
        }

        if (
            intervalSeconds < 1 ||
            intervalSeconds > 3600
        )
        {
            std::cout
                << "\n[!] Monitoring interval must be between "
                << "1 and 3600 seconds.\n";

            return;
        }
    }

    // -------------- Start monitor--------------
    std::cout
        << "\n"
        << "============================================================\n"
        << "                 SLIPNET NETWORK MONITOR\n"
        << "============================================================\n"
        << "\n"
        << " Interface       : "
        << interfaceName
        << "\n"
        << " Interval        : "
        << intervalSeconds
        << " second(s)\n"
        << " Mode            : Continuous\n"
        << " Stop            : Ctrl+C\n"
        << "\n";

    monitor.monitor(
        interfaceName,
        intervalSeconds
    );
}

void CommandHandler::handleNetworkShow(
    const ParsedCommand&
)
{
    const auto& hosts =
        context.network.getHosts();

    const auto& services =
        context.network.getServices();

    const std::size_t hostCount =
        context.network.getHostCount();

    const std::size_t onlineHostCount =
        context.network.getOnlineHostCount();

    std::size_t offlineHostCount = 0;

    if (hostCount >= onlineHostCount)
    {
        offlineHostCount =
            hostCount - onlineHostCount;
    }

    std::size_t openPortCount = 0;

    for (const auto& host : hosts)
    {
        const auto& ports =
            context.network.getPorts(host.ip);

        for (const auto& port : ports)
        {
            if (port.open)
            {
                ++openPortCount;
            }
        }
    }

    //----------------- NETWORK STATE----------------
    std::cout
        << "\n"
        << "============================================================\n"
        << "                     SLIPNET NETWORK STATE\n"
        << "============================================================\n"
        << "\n";

    //------------ Summary---------------------
    std::cout
        << "SUMMARY\n"
        << "------------------------------------------------------------\n"
        << " Hosts discovered : "
        << hostCount
        << '\n'

        << " Hosts online     : "
        << onlineHostCount
        << '\n'

        << " Hosts offline    : "
        << offlineHostCount
        << '\n'

        << " Open ports       : "
        << openPortCount
        << '\n'

        << " Services         : "
        << services.size()
        << '\n';

    //------------------ HOSTS--------------------
    std::cout
        << "\n"
        << "HOSTS\n"
        << "------------------------------------------------------------\n";

    if (hosts.empty())
    {
        std::cout
            << " No hosts discovered.\n";
    }
    else
    {
        std::cout
            << std::left
            << std::setw(18) << "IP ADDRESS"
            << std::setw(24) << "HOSTNAME"
            << std::setw(12) << "STATUS"
            << std::right
            << std::setw(12) << "LATENCY"
            << '\n';

        std::cout
            << "------------------------------------------------------------\n";

        for (const auto& host : hosts)
        {
            std::string hostname =
                host.hostname.empty()
                    ? "-"
                    : host.hostname;

            std::string status;

            if (host.online)
            {
                status = "ONLINE";
            }
            else if (!host.status.empty())
            {
                status = host.status;
            }
            else
            {
                status = "OFFLINE";
            }

            std::cout
                << std::left
                << std::setw(18)
                << host.ip

                << std::setw(24)
                << hostname

                << std::setw(12)
                << status

                << std::right
                << std::fixed
                << std::setprecision(2)
                << std::setw(9)
                << host.latency_ms
                << " ms"
                << '\n';
        }
    }

    //-------------------------- OPEN PORTS------------------
    std::cout
        << "\n"
        << "OPEN PORTS\n"
        << "------------------------------------------------------------\n";

    if (openPortCount == 0)
    {
        std::cout
            << " No open ports detected.\n";
    }
    else
    {
        std::cout
            << std::left
            << std::setw(18) << "HOST"
            << std::setw(10) << "PORT"
            << std::setw(12) << "PROTOCOL"
            << "SERVICE"
            << '\n';

        std::cout
            << "------------------------------------------------------------\n";

        for (const auto& host : hosts)
        {
            const auto& ports =
                context.network.getPorts(host.ip);

            for (const auto& port : ports)
            {
                if (!port.open)
                {
                    continue;
                }

                std::cout
                    << std::left
                    << std::setw(18)
                    << host.ip

                    << std::setw(10)
                    << port.port

                    << std::setw(12)
                    << (
                        port.protocol.empty()
                            ? "-"
                            : port.protocol
                    )

                    << (
                        port.service.empty()
                            ? "-"
                            : port.service
                    )

                    << '\n';
            }
        }
    }

    //----------------- SERVICES---------------------
    std::cout
        << "\n"
        << "DETECTED SERVICES\n"
        << "------------------------------------------------------------\n";

    if (services.empty())
    {
        std::cout
            << " No services detected.\n";
    }
    else
    {
        std::cout
            << std::left
            << std::setw(18) << "HOST"
            << std::setw(10) << "PORT"
            << std::setw(12) << "PROTOCOL"
            << std::setw(20) << "SERVICE"
            << "VERSION"
            << '\n';

        std::cout
            << "------------------------------------------------------------\n";

        for (const auto& service : services)
        {
            std::cout
                << std::left
                << std::setw(18)
                << service.ip

                << std::setw(10)
                << service.port

                << std::setw(12)
                << (
                    service.protocol.empty()
                        ? "-"
                        : service.protocol
                )

                << std::setw(20)
                << (
                    service.service.empty()
                        ? "-"
                        : service.service
                )

                << (
                    service.version.empty()
                        ? "-"
                        : service.version
                )

                << '\n';
        }
    }


    //----------------- END---------------
    std::cout
        << "\n"
        << "============================================================\n"
        << " Network state displayed successfully.\n"
        << "============================================================\n";
}


void CommandHandler::handleNetworkClear(
    const ParsedCommand&
)
{
    const std::size_t hostsBefore =
        context.network.getHostCount();

    const std::size_t onlineBefore =
        context.network.getOnlineHostCount();

    const std::size_t servicesBefore =
        context.network.getServices().size();

    std::size_t openPortsBefore = 0;

    
    // Count open ports before clearing the state.
    for (const auto& host :
         context.network.getHosts())
    {
        const auto& ports =
            context.network.getPorts(host.ip);

        for (const auto& port : ports)
        {
            if (port.open)
            {
                ++openPortsBefore;
            }
        }
    }

    // Clear all collected network intelligence.
    context.network.clear();

    // Verify that the state was actually cleared.
    const bool cleared =
        context.network.getHostCount() == 0 &&
        context.network.getOnlineHostCount() == 0 &&
        context.network.getServices().empty();

    // Display result.
    std::cout
        << "\n"
        << "============================================================\n"
        << "                  SLIPNET NETWORK CLEAR\n"
        << "============================================================\n"
        << "\n";

    if (!cleared)
    {
        std::cout
            << "[!] Failed to completely clear network state.\n"
            << "\n"
            << "Please try again.\n"
            << "\n"
            << "============================================================\n";

        return;
    }

    std::cout
        << "[+] Network state cleared successfully.\n"
        << "\n"

        << "Cleared data\n"
        << "------------------------------------------------------------\n"

        << " Hosts           : "
        << hostsBefore
        << '\n'

        << " Online hosts    : "
        << onlineBefore
        << '\n'

        << " Open ports      : "
        << openPortsBefore
        << '\n'

        << " Services        : "
        << servicesBefore
        << '\n'

        << "\n"

        << "Current state\n"
        << "------------------------------------------------------------\n"

        << " Hosts           : 0\n"
        << " Open ports      : 0\n"
        << " Services        : 0\n"

        << "\n"

        << "============================================================\n";
}


void CommandHandler::handleSecurityDetect(
    const ParsedCommand& command
)
{
    const auto& hosts =
        context.network.getHosts();

    std::cout
        << "\n"
        << "============================================================\n"
        << "                 SLIPNET SECURITY ANALYSIS\n"
        << "============================================================\n"
        << "\n"
        << " Mode        : Passive rule-based analysis\n"
        << " Data source : SlipNet discovery state\n"
        << " Probing     : Disabled\n"
        << " Exploitation: Disabled\n";

    //---------------- Argument validation-----------------------
    if (command.arguments.size() > 1)
    {
        std::cout
            << "\n[!] Invalid arguments.\n"
            << "\nUsage:\n"
            << "  sec|:detect\n"
            << "  sec|:detect <IP>\n"
            << "\n"
            << "Examples:\n"
            << "  sec|:detect\n"
            << "  sec|:detect 192.168.1.10\n"
            << "\n"
            << "============================================================\n";

        return;
    }

    if (hosts.empty())
    {
        std::cout
            << "\n[!] No discovered hosts available.\n"
            << "\n[*] Security analysis requires information\n"
            << "    collected by SlipNet first.\n"
            << "\n[*] Recommended sequence:\n"
            << "    ip|:seek\n"
            << "    port|:scan <IP>\n"
            << "    svc|:detect <IP>\n"
            << "    sec|:detect\n"
            << "\n"
            << "============================================================\n";

        return;
    }

    //------------------- Determine analysis scope----------------
    std::string targetIp;

    if (!command.arguments.empty())
    {
        targetIp =
            command.arguments[0];

        bool discovered = false;

        for (const auto& host : hosts)
        {
            if (host.ip == targetIp)
            {
                discovered = true;
                break;
            }
        }

        if (!discovered)
        {
            std::cout
                << "\n[!] Host is not present in SlipNet's "
                << "discovered network state.\n"
                << "    IP: "
                << targetIp
                << "\n"
                << "\n[*] Run ip|:seek first or use an IP "
                << "already discovered by SlipNet.\n"
                << "\n"
                << "============================================================\n";

            return;
        }
    }

    SecurityDetector detector;

    std::size_t hostsAnalyzed = 0;
    std::size_t hostsWithFindings = 0;

    std::size_t totalAlerts = 0;
    std::size_t highAlerts = 0;
    std::size_t mediumAlerts = 0;
    std::size_t lowAlerts = 0;
    std::size_t infoAlerts = 0;


    //--------------- Analyze hosts---------------
    for (const auto& host : hosts)
    {
        if (
            !targetIp.empty() &&
            host.ip != targetIp
        )
        {
            continue;
        }

        ++hostsAnalyzed;

        const auto& ports =
            context.network.getPorts(
                host.ip
            );

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

        const auto alerts =
            detector.analyze(
                host.ip,
                ports,
                hostServices
            );

        if (!alerts.empty())
        {
            ++hostsWithFindings;
        }

        int openPorts = 0;

        for (const auto& port : ports)
        {
            if (port.open)
            {
                ++openPorts;
            }
        }

        std::cout
            << "\n"
            << "HOST: "
            << host.ip
            << "\n"
            << "------------------------------------------------------------\n"
            << "Status       : "
            << (
                host.status.empty()
                    ? (host.online ? "ONLINE" : "OFFLINE")
                    : host.status
            )
            << "\n"
            << "Open ports   : "
            << openPorts
            << "\n"
            << "Services     : "
            << hostServices.size()
            << "\n"
            << "Findings     : "
            << alerts.size()
            << "\n";

        if (alerts.empty())
        {
            std::cout
                << "\n"
                << "[+] No rule-based security findings.\n";

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


    //-----------------------Summary--------------------
    std::cout
        << "\n"
        << "============================================================\n"
        << "                 SECURITY SUMMARY\n"
        << "============================================================\n"
        << "\n"
        << "Hosts analyzed : "
        << hostsAnalyzed
        << "\n"
        << "Hosts findings : "
        << hostsWithFindings
        << "\n"
        << "Total findings : "
        << totalAlerts
        << "\n"
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
            << "\n"
            << "[+] No rule-based security findings detected.\n";
    }
    else
    {
        std::cout
            << "\n"
            << "[!] Security findings require review.\n"
            << "[*] Findings represent detected exposure patterns,\n"
            << "    not proof of compromise or exploitable vulnerability.\n";
    }

    std::cout
        << "\n"
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

    //----------------- Platform information-------------------------
    const auto platformInfo =
        slipnet::platform::getSessionPlatformInfo();

    //-------------- Network state--------------
    std::size_t discoveredPorts = 0;

    std::size_t openPorts = 0;

    for (
        const auto& host :
        context.network.getHosts()
    )
    {
        const auto& ports =
            context.network.getPorts(
                host.ip
            );

        discoveredPorts +=
            ports.size();

        for (const auto& port : ports)
        {
            if (port.open)
            {
                ++openPorts;
            }
        }
    }

    //----------------- Services---------------
    const std::size_t serviceCount =
        context.network
            .getServices()
            .size();

    //--------------- Session information-------------------
    std::cout
        << "\n"
        << "================================================================\n"
        << "                    SESSION INFORMATION\n"
        << "================================================================\n";

    //------------------- SlipNet----------------
    std::cout
        << "\n"
        << " SlipNet\n"
        << "----------------------------------------------------------------\n"
        << "  Version          : "
        << context.version
        << "\n"
        << "  Session state    : "
        << (
            context.running
                ? "ACTIVE"
                : "STOPPED"
        )
        << "\n"
        << "  Operating mode   : CLI\n";

    //----------- Platform--------------
    std::cout
        << "\n"
        << " Platform\n"
        << "----------------------------------------------------------------\n"
        << "  Operating system : "
        << platformInfo.operatingSystem
        << "\n"
        << "  Architecture     : "
        << platformInfo.architecture
        << "\n"
        << "  Hostname         : "
        << platformInfo.hostname
        << "\n";

    //------------------Network state----------------
    std::cout
        << "\n"
        << " Network State\n"
        << "----------------------------------------------------------------\n"
        << "  Hosts discovered : "
        << context.network.getHostCount()
        << "\n"
        << "  Hosts online     : "
        << context.network.getOnlineHostCount()
        << "\n"
        << "  Ports discovered : "
        << discoveredPorts
        << "\n"
        << "  Open ports       : "
        << openPorts
        << "\n"
        << "  Services         : "
        << serviceCount
        << "\n";

    //---------------- Session notes----------------------
    std::cout
        << "\n"
        << " Session Notes\n"
        << "----------------------------------------------------------------\n"
        << "  Network data     : In-memory\n"
        << "  Persistence      : Not enabled\n"
        << "  Platform backend : "
        << platformInfo.operatingSystem
        << "\n";


    std::cout
        << "\n"
        << "================================================================\n";
}


void CommandHandler::handleMacResolve(
    const ParsedCommand& command
)
{
    if (command.arguments.size() != 1)
    {
        std::cout
            << "\nUsage: mac|:resolve <IP>\n";

        return;
    }

    const std::string& ip =
        command.arguments[0];

    std::cout
        << "\n[*] Resolving MAC address for "
        << ip
        << "...\n";

    MacResolver resolver;

    MacResolution result =
        resolver.resolve(ip);

    if (!result.found)
    {
        std::cout
            << "[!] MAC address not available.\n"
            << "[*] The target may not be present in the local ARP/neighbor table.\n";

        return;
    }

    std::cout
        << "\n============================================================\n"
        << "                     MAC RESOLUTION\n"
        << "============================================================\n"
        << "IP Address  : " << result.ip << '\n'
        << "MAC Address : " << result.mac << '\n'
        << "Vendor      : " << result.vendor << '\n'
        << "Interface   : " << result.interfaceName << '\n'
        << "============================================================\n";
}

void CommandHandler::handleDnsResolve(
    const ParsedCommand& command
)
{
    if (command.arguments.size() != 1)
    {
        std::cout
            << "\n"
            << "Usage: dns|:resolve <hostname|IP>\n";

        return;
    }

    const std::string& input =
        command.arguments[0];

    std::cout
        << "\n"
        << "[*] Resolving DNS information for "
        << input
        << "...\n";

    DNSResolver resolver;

    const DNSResult result =
        resolver.resolve(input);

    const bool inputIsIP =
        resolver.isIPAddress(result.input);

    std::cout
        << "\n"
        << "============================================================\n"
        << "                 SLIPNET :: DNS RESOLUTION\n"
        << "============================================================\n"
        << "\n"
        << " INPUT\n"
        << "------------------------------------------------------------\n"
        << " "
        << result.input
        << "\n";

    /*
     * --------------------------------------------------------
     * Reverse DNS
     * --------------------------------------------------------
     */

    if (inputIsIP)
    {
        std::cout
            << "\n"
            << " REVERSE DNS\n"
            << "------------------------------------------------------------\n";

        if (!result.reverseName.empty())
        {
            std::cout
                << " Hostname     : "
                << result.reverseName
                << "\n"
                << " Status       : PTR record found\n";
        }
        else
        {
            std::cout
                << " Hostname     : Not available\n"
                << " Status       : No PTR record\n";
        }
    }

    /*
     * --------------------------------------------------------
     * Canonical Name
     * --------------------------------------------------------
     */

    if (!result.canonicalName.empty())
    {
        std::cout
            << "\n"
            << " CANONICAL NAME\n"
            << "------------------------------------------------------------\n"
            << " "
            << result.canonicalName
            << "\n";
    }

    /*
     * --------------------------------------------------------
     * Resolved Addresses
     * --------------------------------------------------------
     */

    if (!result.addresses.empty())
    {
        std::cout
            << "\n"
            << " RESOLVED ADDRESSES\n"
            << "------------------------------------------------------------\n";

        for (const auto& address : result.addresses)
        {
            std::cout
                << "  • "
                << address
                << "\n";
        }
    }

    /*
     * --------------------------------------------------------
     * Result
     * --------------------------------------------------------
     */

    std::cout
        << "\n"
        << " RESULT\n"
        << "------------------------------------------------------------\n";

    if (inputIsIP)
    {
        if (!result.reverseName.empty())
        {
            std::cout
                << " Status       : RESOLVED\n"
                << " Hostname     : "
                << result.reverseName
                << "\n";
        }
        else
        {
            std::cout
                << " Status       : NO PTR RECORD\n"
                << " Note         : The target IP has no reverse DNS hostname.\n";
        }
    }
    else
    {
        if (!result.addresses.empty())
        {
            std::cout
                << " Status       : RESOLVED\n";
        }
        else
        {
            std::cout
                << " Status       : FAILED\n"
                << " Note         : No DNS addresses were returned.\n";
        }
    }

    /*
     * --------------------------------------------------------
     * Final status
     * --------------------------------------------------------
     */

    std::cout << "\n";

    if (result.success)
    {
        std::cout
            << "[+] DNS resolution completed successfully.\n";
    }
    else if (
        inputIsIP &&
        result.reverseName.empty()
    )
    {
        std::cout
            << "[*] Reverse DNS lookup completed.\n"
            << "[*] No PTR record was found for this IP address.\n";
    }
    else
    {
        std::cout
            << "[!] DNS resolution failed.\n"
            << "[*] Verify the hostname/IP and DNS availability.\n";
    }
}

void CommandHandler::handleOSFingerprint(
    const ParsedCommand& command
)
{
    if (command.arguments.size() != 1)
    {
        std::cout
            << "\n"
            << "Usage: os|:fingerprint <IP>\n"
            << "\n"
            << "Example:\n"
            << "  os|:fingerprint 192.168.1.10\n";

        return;
    }


    const std::string& target =
        command.arguments[0];


    std::cout
        << "\n"
        << "[*] Fingerprinting "
        << target
        << "...\n";


    OSFingerprinter fingerprinter;

    const OSFingerprint result =
        fingerprinter.fingerprint(
            target
        );


    /*
     * --------------------------------------------------------
     * ASCII-safe presentation
     * --------------------------------------------------------
     *
     * Do not use Unicode box-drawing characters here.
     *
     * SlipNet is intended to run on:
     *
     *   - Windows CMD
     *   - PowerShell
     *   - Windows Terminal
     *   - MSYS2 UCRT64
     *   - Linux terminals
     *
     * ASCII guarantees consistent output across platforms.
     */

    std::cout
        << "\n"
        << "+------------------------------------------------------------+\n"
        << "| SLIPNET :: OS FINGERPRINT                                  |\n"
        << "+------------------------------------------------------------+\n"
        << "\n"
        << " TARGET\n"
        << " ------------------------------------------------------------\n"
        << " IP Address       : "
        << result.target
        << "\n";


    /*
     * --------------------------------------------------------
     * Fingerprint result
     * --------------------------------------------------------
     */

    if (!result.detected)
    {
        std::cout
            << "\n"
            << " FINGERPRINT\n"
            << " ------------------------------------------------------------\n"
            << " Operating System : Unknown\n"
            << " Observed TTL     : Unavailable\n"
            << " Confidence       : LOW\n"
            << " Method            : TTL heuristic\n"
            << "\n"
            << "[!] Unable to obtain a usable OS fingerprint.\n"
            << "[*] The target may be unreachable or filtering ICMP.\n"
            << "+------------------------------------------------------------+\n";

        return;
    }


    std::cout
        << "\n"
        << " FINGERPRINT\n"
        << " ------------------------------------------------------------\n"
        << " Operating System : "
        << result.operatingSystem
        << "\n"
        << " Observed TTL     : "
        << result.ttl
        << "\n"
        << " Confidence       : "
        << result.confidence
        << "\n"
        << " Method            : TTL heuristic\n";


    /*
     * --------------------------------------------------------
     * Interpretation
     * --------------------------------------------------------
     */

    std::cout
        << "\n"
        << " ANALYSIS\n"
        << " ------------------------------------------------------------\n"
        << " TTL-based classification is heuristic.\n"
        << " It does not guarantee the target operating system.\n";


    std::cout
        << "\n"
        << "[+] Heuristic OS fingerprint completed successfully.\n"
        << "[*] Result is based on observed network characteristics.\n"
        << "+------------------------------------------------------------+\n";
}

void CommandHandler::handleBannerGrab(
    const ParsedCommand& command
)
{
    if (command.arguments.size() != 2)
    {
        std::cout
            << "\nUsage: banner|:grab <IP> <PORT>\n";

        return;
    }

    int port;

    try
    {
        port =
            std::stoi(
                command.arguments[1]
            );
    }
    catch (...)
    {
        std::cout
            << "[!] Invalid port.\n";

        return;
    }

    if (port < 1 || port > 65535)
    {
        std::cout
            << "[!] Port must be between 1 and 65535.\n";

        return;
    }

    BannerGrabber grabber;

    BannerResult result =
        grabber.grab(
            command.arguments[0],
            port
        );

    std::cout
        << "\n"
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: SERVICE BANNER                                   │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n"
        << "\n"

        << " TARGET\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " IP Address     "
        << result.host
        << "\n"
        << " Port           "
        << result.port
        << "\n"
        << " Protocol       "
        << result.protocol
        << "\n"
        << " Connection     "
        << (result.connected ? "ESTABLISHED" : "FAILED")
        << "\n";

    if (!result.banner.empty())
    {
        std::cout
            << "\n"
            << " BANNER\n"
            << " ────────────────────────────────────────────────────────────\n"
            << " "
            << result.banner
            << "\n\n"
            << "[+] Service banner retrieved successfully.\n";
    }
    else if (result.connected)
    {
        std::cout
            << "\n"
            << "[*] TCP connection established.\n"
            << "[!] The service did not return an application banner.\n";
    }
    else
    {
        std::cout
            << "\n"
            << "[!] Unable to establish a TCP connection.\n"
            << "[*] Verify that the host is reachable and the port is open.\n";
    }

    std::cout
        << "\n"
        << "============================================================\n";
}

void CommandHandler::handleSubnetCalc(
    const ParsedCommand& command
)
{
    if (command.arguments.size() != 1)
    {
        std::cout
            << "\nUsage: subnet|:calc <CIDR>\n"
            << "Example: subnet|:calc 192.168.1.0/24\n";

        return;
    }

    const std::string& cidr =
        command.arguments[0];

    std::cout
        << "\n[*] Calculating subnet information for "
        << cidr
        << "...\n";

    SubnetCalculator calculator;

    SubnetInfo result =
        calculator.calculate(cidr);

    if (!result.valid)
    {
        std::cout
            << "\n╭──────────────────────────────────────────────────────────────╮\n"
            << "│ SLIPNET :: SUBNET CALCULATOR                                │\n"
            << "╰──────────────────────────────────────────────────────────────╯\n"
            << "\n"
            << "[!] Invalid IPv4 CIDR notation.\n"
            << "[*] Example: subnet|:calc 192.168.1.0/24\n";

        return;
    }

    std::cout
        << "\n╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: SUBNET CALCULATOR                                │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n"
        << "\n";

    std::cout
        << " NETWORK\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " CIDR          "
        << result.input
        << "\n"
        << " Network       "
        << result.network
        << "\n"
        << " Netmask       "
        << result.netmask
        << "\n"
        << " Wildcard      "
        << result.wildcard
        << "\n"
        << " Prefix        /"
        << result.prefix
        << "\n\n";

    std::cout
        << " ADDRESS SPACE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Total         "
        << result.totalAddresses
        << "\n"
        << " Usable Hosts  "
        << result.usableHosts
        << "\n"
        << " First Host    "
        << result.firstHost
        << "\n"
        << " Last Host     "
        << result.lastHost
        << "\n"
        << " Broadcast     "
        << result.broadcast
        << "\n\n";

    std::cout
        << " ADDRESS CLASSIFICATION\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Type          "
        << result.addressType
        << "\n\n";

    std::cout
        << "[+] Subnet calculation completed successfully.\n";
}

void CommandHandler::handleVulnScan(
    const ParsedCommand& command
)
{
    std::cout
        << "\n============================================================\n"
        << "                 SLIPNET VULNERABILITY ENGINE\n"
        << "============================================================\n";

    const auto& services =
        context.network.getServices();

    if (services.empty())
    {
        std::cout
            << "[!] No service intelligence available.\n"
            << "[*] Run:\n"
            << "    ip|:seek\n"
            << "    port|:scan <IP>\n"
            << "    svc|:detect <IP>\n"
            << "    vuln|:scan\n"
            << "\n"
            << "============================================================\n";

        return;
    }

    std::vector<ServiceInfo> targets;

    if (command.arguments.empty())
    {
        targets =
            services;
    }
    else
    {
        const std::string& target =
            command.arguments[0];

        for (const auto& service : services)
        {
            if (service.ip == target)
            {
                targets.push_back(service);
            }
        }

        if (targets.empty())
        {
            std::cout
                << "[!] No detected services for "
                << target
                << ".\n";

            return;
        }
    }

    VulnerabilityScanner scanner;

    const auto findings =
        scanner.scan(targets);

    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
    int info = 0;

    for (const auto& finding : findings)
    {
        switch (finding.severity)
        {
            case VulnerabilitySeverity::CRITICAL:
                ++critical;
                break;

            case VulnerabilitySeverity::HIGH:
                ++high;
                break;

            case VulnerabilitySeverity::MEDIUM:
                ++medium;
                break;

            case VulnerabilitySeverity::LOW:
                ++low;
                break;

            case VulnerabilitySeverity::INFO:
                ++info;
                break;
        }
    }

    std::cout
        << "\n"
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: VULNERABILITY ASSESSMENT                         │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n\n"

        << " SCOPE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Services Analyzed     "
        << targets.size()
        << "\n"
        << " Findings              "
        << findings.size()
        << "\n\n"

        << " RISK SUMMARY\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Critical              "
        << critical
        << "\n"
        << " High                  "
        << high
        << "\n"
        << " Medium                "
        << medium
        << "\n"
        << " Low                   "
        << low
        << "\n"
        << " Informational         "
        << info
        << "\n\n";

    if (findings.empty())
    {
        std::cout
            << "[+] No known exposure heuristics detected.\n"
            << "[*] This does not prove that the target is vulnerability-free.\n";
    }
    else
    {
        for (const auto& finding : findings)
        {
            std::string severity;

            switch (finding.severity)
            {
                case VulnerabilitySeverity::CRITICAL:
                    severity = "CRITICAL";
                    break;

                case VulnerabilitySeverity::HIGH:
                    severity = "HIGH";
                    break;

                case VulnerabilitySeverity::MEDIUM:
                    severity = "MEDIUM";
                    break;

                case VulnerabilitySeverity::LOW:
                    severity = "LOW";
                    break;

                default:
                    severity = "INFO";
                    break;
            }

            std::cout
                << " ┌──────────────────────────────────────────────────────────\n"
                << " │ [" << severity << "] "
                << finding.id
                << "\n"
                << " │ Target       : "
                << finding.host
                << ":"
                << finding.port
                << "\n"
                << " │ Service      : "
                << finding.service;

            if (!finding.version.empty())
            {
                std::cout
                    << " "
                    << finding.version;
            }

            std::cout
                << "\n"
                << " │ Title        : "
                << finding.title
                << "\n"
                << " │ Confidence   : "
                << finding.confidence
                << "%\n"
                << " │ Evidence     : "
                << finding.evidence
                << "\n"
                << " │ Description  : "
                << finding.description
                << "\n"
                << " │ Remediation  : "
                << finding.remediation
                << "\n"
                << " └──────────────────────────────────────────────────────────\n";
        }
    }

    std::cout
        << "\n"
        << " ASSESSMENT STATUS\n"
        << " ────────────────────────────────────────────────────────────\n";

    if (critical > 0)
    {
        std::cout
            << " Risk Level     CRITICAL\n";
    }
    else if (high > 0)
    {
        std::cout
            << " Risk Level     HIGH\n";
    }
    else if (medium > 0)
    {
        std::cout
            << " Risk Level     MEDIUM\n";
    }
    else if (low > 0)
    {
        std::cout
            << " Risk Level     LOW\n";
    }
    else
    {
        std::cout
            << " Risk Level     INFORMATIONAL\n";
    }

    std::cout
        << "\n"
        << "[+] Vulnerability assessment completed.\n"
        << "[*] Findings are heuristic security indicators, "
        "not confirmed CVE diagnoses.\n"
        << "\n"
        << "============================================================\n";
}


void CommandHandler::handleCredCheck(
    const ParsedCommand& command
)
{
    std::cout
        << "\n============================================================\n"
        << "                 SLIPNET CREDENTIAL ENGINE\n"
        << "============================================================\n";

    if (command.arguments.size() > 1)
    {
        std::cout
            << "[!] Usage: cred|:check [IP]\n"
            << "============================================================\n";

        return;
    }

    const auto& services =
        context.network.getServices();

    if (services.empty())
    {
        std::cout
            << "[!] No service intelligence available.\n"
            << "[*] Run:\n"
            << "    ip|:seek\n"
            << "    port|:scan <IP>\n"
            << "    svc|:detect <IP>\n"
            << "    cred|:check\n"
            << "\n"
            << "============================================================\n";

        return;
    }

    std::vector<ServiceInfo> targets;

    if (command.arguments.empty())
    {
        targets = services;
    }
    else
    {
        const std::string& target =
            command.arguments[0];

        for (const auto& service : services)
        {
            if (service.ip == target)
            {
                targets.push_back(service);
            }
        }

        if (targets.empty())
        {
            std::cout
                << "[!] No detected services for "
                << target
                << ".\n"
                << "============================================================\n";

            return;
        }
    }

    std::cout
        << "\n[*] Analyzing credential exposure...\n";

    CredentialChecker checker;

    const auto findings =
        checker.check(targets);

    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
    int info = 0;

    for (const auto& finding : findings)
    {
        switch (finding.risk)
        {
            case CredentialRisk::CRITICAL:
                ++critical;
                break;

            case CredentialRisk::HIGH:
                ++high;
                break;

            case CredentialRisk::MEDIUM:
                ++medium;
                break;

            case CredentialRisk::LOW:
                ++low;
                break;

            default:
                ++info;
                break;
        }
    }

    std::cout
        << "\n"
        << " SCOPE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Services Analyzed     "
        << targets.size()
        << "\n"
        << " Findings              "
        << findings.size()
        << "\n\n"
        << " CREDENTIAL RISK\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Critical              "
        << critical
        << "\n"
        << " High                  "
        << high
        << "\n"
        << " Medium                "
        << medium
        << "\n"
        << " Low                   "
        << low
        << "\n"
        << " Informational         "
        << info
        << "\n";

    for (const auto& finding : findings)
    {
        std::string risk;

        switch (finding.risk)
        {
            case CredentialRisk::CRITICAL:
                risk = "CRITICAL";
                break;

            case CredentialRisk::HIGH:
                risk = "HIGH";
                break;

            case CredentialRisk::MEDIUM:
                risk = "MEDIUM";
                break;

            case CredentialRisk::LOW:
                risk = "LOW";
                break;

            default:
                risk = "INFO";
                break;
        }

        std::cout
            << "\n[" << risk << "] "
            << finding.id
            << "\n"
            << "Target      : "
            << finding.host
            << ":"
            << finding.port
            << "\n"
            << "Service     : "
            << finding.service
            << "\n"
            << "Title       : "
            << finding.title
            << "\n"
            << "Description : "
            << finding.description
            << "\n"
            << "Evidence    : "
            << finding.evidence
            << "\n"
            << "Confidence  : "
            << finding.confidence
            << "%\n"
            << "Remediation : "
            << finding.remediation
            << "\n";
    }

    if (findings.empty())
    {
        std::cout
            << "\n[+] No credential exposure heuristics detected.\n"
            << "[*] No credentials were collected, tested or "
               "brute-forced.\n";
    }

    std::string overallRisk =
        "INFORMATIONAL";

    if (critical > 0)
        overallRisk = "CRITICAL";
    else if (high > 0)
        overallRisk = "HIGH";
    else if (medium > 0)
        overallRisk = "MEDIUM";
    else if (low > 0)
        overallRisk = "LOW";

    std::cout
        << "\n"
        << " ASSESSMENT STATUS\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Risk Level     "
        << overallRisk
        << "\n\n"
        << "[+] Credential assessment completed.\n"
        << "[*] Findings indicate potential credential exposure risks; "
           "they are not proof of compromised credentials.\n"
        << "\n============================================================\n";
}


void CommandHandler::handleSSLAudit(
    const ParsedCommand& command
)
{
    std::cout
        << "\n"
        << "╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: TLS / SSL AUDIT                                 │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n";

    if (
        command.arguments.empty() ||
        command.arguments.size() > 2
    )
    {
        std::cout
            << "\nUsage:\n"
            << "  ssl|:audit <IP|HOSTNAME>\n"
            << "  ssl|:audit <IP|HOSTNAME> <PORT>\n";

        return;
    }

    const std::string host =
        command.arguments[0];

    int port = 443;

    if (command.arguments.size() == 2)
    {
        try
        {
            port =
                std::stoi(
                    command.arguments[1]
                );
        }
        catch (...)
        {
            std::cout
                << "\n[!] Invalid port.\n";

            return;
        }

        if (port < 1 || port > 65535)
        {
            std::cout
                << "\n[!] Port must be between 1 and 65535.\n";

            return;
        }
    }

    std::cout
        << "\n"
        << "[*] Auditing TLS service...\n";

    SSLAuditor auditor;

    const SSLAuditResult result =
        auditor.audit(
            host,
            port
        );

    std::cout
        << "\n TARGET\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Host           " << result.host << '\n'
        << " Port           " << result.port << '\n'
        << " TCP Connection "
        << (result.connected ? "ESTABLISHED" : "FAILED")
        << '\n';

    if (!result.connected)
    {
        std::cout
            << "\n[!] Unable to establish a TCP connection.\n"
            << "[*] Verify that the host is reachable and the "
               "specified port is open.\n"
            << "\n[+] TLS audit completed.\n"
            << "============================================================\n";

        return;
    }

    if (!result.tlsEstablished)
    {
        std::cout
            << "\n[!] TCP connection succeeded, but TLS "
               "negotiation failed.\n";

        for (const auto& finding : result.findings)
        {
            std::cout
                << "\n[" << finding.id << "] "
                << finding.title << '\n'
                << "  " << finding.description << '\n'
                << "  Evidence    : "
                << finding.evidence << '\n'
                << "  Remediation : "
                << finding.remediation << '\n';
        }

        std::cout
            << "\n============================================================\n";

        return;
    }

    std::cout
        << "\n TLS SESSION\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " TLS Version    " << result.tlsVersion << '\n'
        << " Cipher         " << result.cipher << '\n';

    std::cout
        << "\n CERTIFICATE\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Subject        "
        << (result.subject.empty()
                ? "Unavailable"
                : result.subject)
        << '\n'
        << " Issuer         "
        << (result.issuer.empty()
                ? "Unavailable"
                : result.issuer)
        << '\n'
        << " Valid From     "
        << (result.validFrom.empty()
                ? "Unavailable"
                : result.validFrom)
        << '\n'
        << " Valid Until    "
        << (result.validUntil.empty()
                ? "Unavailable"
                : result.validUntil)
        << '\n'
        << " Certificate    "
        << (result.certificateValid ? "VALID" : "INVALID")
        << '\n'
        << " Self-Signed    "
        << (result.selfSigned ? "YES" : "NO")
        << '\n';

    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
    int info = 0;

    for (const auto& finding : result.findings)
    {
        switch (finding.severity)
        {
            case SSLSeverity::CRITICAL:
                ++critical;
                break;

            case SSLSeverity::HIGH:
                ++high;
                break;

            case SSLSeverity::MEDIUM:
                ++medium;
                break;

            case SSLSeverity::LOW:
                ++low;
                break;

            default:
                ++info;
                break;
        }
    }

    std::cout
        << "\n FINDINGS\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Critical       " << critical << '\n'
        << " High           " << high << '\n'
        << " Medium         " << medium << '\n'
        << " Low            " << low << '\n'
        << " Informational  " << info << '\n';

    if (result.findings.empty())
    {
        std::cout
            << "\n[+] No TLS security indicators detected.\n";
    }
    else
    {
        for (const auto& finding : result.findings)
        {
            std::string severity;

            switch (finding.severity)
            {
                case SSLSeverity::CRITICAL:
                    severity = "CRITICAL";
                    break;

                case SSLSeverity::HIGH:
                    severity = "HIGH";
                    break;

                case SSLSeverity::MEDIUM:
                    severity = "MEDIUM";
                    break;

                case SSLSeverity::LOW:
                    severity = "LOW";
                    break;

                default:
                    severity = "INFO";
                    break;
            }

            std::cout
                << "\n[" << severity << "] "
                << finding.id << '\n'
                << "Title        : "
                << finding.title << '\n'
                << "Description  : "
                << finding.description << '\n'
                << "Evidence     : "
                << finding.evidence << '\n'
                << "Confidence   : "
                << finding.confidence << "%\n"
                << "Remediation  : "
                << finding.remediation << '\n';
        }
    }

    std::string riskLevel = "INFORMATIONAL";

    if (critical > 0)
    {
        riskLevel = "CRITICAL";
    }
    else if (high > 0)
    {
        riskLevel = "HIGH";
    }
    else if (medium > 0)
    {
        riskLevel = "MEDIUM";
    }
    else if (low > 0)
    {
        riskLevel = "LOW";
    }

    std::cout
        << "\n ASSESSMENT STATUS\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Risk Level     " << riskLevel << '\n'
        << "\n[+] TLS audit completed.\n"
        << "[*] Findings are security indicators and should be "
           "validated against the service configuration.\n"
        << "\n============================================================\n";
}

void CommandHandler::handleFirewallProbe(
    const ParsedCommand& command
)
{
    if (
        command.arguments.size() != 1
    )
    {
        std::cout
            << "\nUsage: firewall|:probe <IP>\n"
            << "Example:\n"
            << "  firewall|:probe 192.168.1.1\n";

        return;
    }

    const std::string& ip =
        command.arguments[0];

    /*
     * Common TCP ports selected for defensive
     * exposure analysis.
     *
     * These are intentionally limited rather than
     * performing a large arbitrary port scan.
     */
    const std::vector<int> probePorts =
    {
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        143,
        443,
        445,
        3306,
        3389,
        5432,
        6379,
        8080
    };

    std::cout
        << "\n╭──────────────────────────────────────────────────────────────╮\n"
        << "│ SLIPNET :: FIREWALL PROBE                                  │\n"
        << "╰──────────────────────────────────────────────────────────────╯\n"
        << "\n TARGET\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Host              "
        << ip
        << "\n"
        << " Ports Tested      "
        << probePorts.size()
        << "\n"
        << " Timeout           1500 ms\n"
        << "\n[*] Probing TCP response behavior...\n";

    FirewallProbe probe;

    const auto report =
        probe.analyze(
            ip,
            probePorts
        );

    std::cout
        << "\n RESULTS\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Port       State          Latency\n"
        << " ────────────────────────────────────────────────────────────\n";

    for (
        const auto& observation :
        report.observations
    )
    {
        std::cout
            << " "
            << observation.port;

        if (observation.port < 100)
            std::cout << "        ";
        else if (observation.port < 1000)
            std::cout << "       ";
        else
            std::cout << "      ";

        std::string state;

        switch (observation.state)
        {
            case FirewallState::OPEN:
                state = "OPEN";
                break;

            case FirewallState::CLOSED:
                state = "CLOSED";
                break;

            case FirewallState::FILTERED:
                state = "FILTERED";
                break;

            default:
                state = "UNKNOWN";
                break;
        }

        std::cout
            << state;

        if (state.length() < 9)
            std::cout << "        ";
        else
            std::cout << "     ";

        if (
            observation.latencyMs >= 0
        )
        {
            std::cout
                << observation.latencyMs
                << " ms";
        }
        else
        {
            std::cout
                << "--";
        }

        std::cout << '\n';
    }

    std::cout
        << " ────────────────────────────────────────────────────────────\n"
        << "\n ANALYSIS\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " Open              "
        << report.open
        << '\n'
        << " Closed            "
        << report.closed
        << '\n'
        << " Filtered          "
        << report.filtered
        << '\n'
        << " Unknown           "
        << report.unknown
        << '\n';

    std::cout
        << "\n FIREWALL EVIDENCE\n"
        << " ────────────────────────────────────────────────────────────\n";

    if (
        report.hasEvidenceOfFiltering
    )
    {
        std::cout
            << " [+] Filtering behavior observed on "
            << report.filtered
            << " port(s).\n"
            << " [*] Silent TCP timeouts may indicate packet filtering\n"
            << "     or traffic dropping.\n";
    }
    else
    {
        std::cout
            << " [*] No direct filtering behavior observed.\n";
    }

    std::cout
        << "\n CONCLUSION\n"
        << " ────────────────────────────────────────────────────────────\n"
        << " "
        << report.conclusion
        << '\n';

    std::cout
        << "\n [!] Important: firewall behavior cannot be determined\n"
        << "     with certainty from TCP connection behavior alone.\n"
        << "     Results are network observations, not proof of a\n"
        << "     specific firewall product or configuration.\n";

    std::cout
        << "\n[+] Firewall probe completed successfully.\n"
        << "\n============================================================\n";
}

void CommandHandler::handleSystemInfo(
    const ParsedCommand& command
)
{
    SystemInfoProvider provider;

    const SystemInfo info =
        provider.collect();

    provider.display(info);
}