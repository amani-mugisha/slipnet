#pragma once

#include <string>
#include <vector>

//   -----------------SlipNet Command System--------------------
//  
//   This file defines all commands understood by SlipNet.
  
//   Command format:

//      category|:action [arguments]
  
//   -------------Hints---------------
//       ip|:seek
//       host|:find 192.168.1.1
//       port|:scan 192.168.1.1
//       svc|:detect 192.168.1.1
//       topo|:map
//       pkt|:capture
//       pkt|:inspect
//       net|:monitor
//       net|:show
//       net|:clear
//       sec|:detect
//       ai|:analyze
//       session|:info
//       help
//       fire


 //----------------- CommandType---------------------
 // Internal representation of a SlipNet command.
 
enum class CommandType
{

     // Network discovery
    IP_SEEK,

    
     // Host availability
    HOST_FIND,


     // Port scanning
    PORT_SCAN,


     //Service detection
    SERVICE_DETECT,


    //network topology
    TOPOLOGY_MAP,

    
    //Packet capture
    PACKET_CAPTURE,

    // Packet inspection
    PACKET_INSPECT,

    //Network monitoring
    NETWORK_MONITOR,

    //Display collected network information
    NETWORK_SHOW,

    //Clear collected network information
    NETWORK_CLEAR,

    //Security analysis
    SECURITY_DETECT,

    // AI analysis
    AI_ANALYZE,

    //Session information
    SESSION_INFO,

    //MAC address resolution
    MAC_RESOLVE,

    //DNS resolution
    DNS_RESOLVE,

    //Operating system fingerprinting
    OS_FINGERPRINT,

    //Service banner grabbing
    BANNER_GRAB,

    //IPv4 subnet calculation
    SUBNET_CALC,

    //Vulnerability assessment
    VULN_SCAN,

    //Credential security audit
    CRED_CHECK,

    //TLS/SSL certificate audit
    SSL_AUDIT,

    //Firewall / port filtering analysis
    FIREWALL_PROBE,

    //System
    SYSTEM_INFO,

    //Help
    HELP,

    //Exit SlipNet
    EXIT,

    //Invalid / unknown command
    UNKNOWN
};

struct ParsedCommand
{
    
    //Type of command.
    CommandType type = CommandType::UNKNOWN;

    // Original command entered by the user.
    std::string raw;

    //Command arguments.
    std::vector<std::string> arguments;
};



 //---------------CommandParser-------------------
 // Converts user input into ParsedCommand objects.

class CommandParser
{
public:

    
    //Parse a complete command line.
    ParsedCommand parse(
        const std::string& input
    ) const;


private:

    
    // Convert command text into CommandType.
     
    CommandType identifyCommand(
        const std::string& command
    ) const;


    
    // Split input into tokens.
    std::vector<std::string> tokenize(
        const std::string& input
    ) const;
};


//-----------------------CommandUtilities----------------------
// Helper functions for displaying command information.
 
namespace CommandUtilities
{
    // Convert CommandType to readable text.
    std::string commandName(
        CommandType type
    );


    // Display SlipNet help.
    void printHelp();

    // Check whether a command requiresan argument.
    bool requiresArgument(
        CommandType type
    );
}