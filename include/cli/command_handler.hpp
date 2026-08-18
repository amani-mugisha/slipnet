#pragma once

#include "cli/command_parser.hpp"
#include "core/engine_context.hpp"


class CommandHandler
{
public:

    explicit CommandHandler(
        EngineContext& context
    );


    bool execute(
        const ParsedCommand& command
    );


private:

    EngineContext& context;


    void handleIpSeek(
        const ParsedCommand& command
    );

    void handleHostFind(
        const ParsedCommand& command
    );

    void handlePortScan(
        const ParsedCommand& command
    );

    void handleServiceDetect(
        const ParsedCommand& command
    );

    void handleTopologyMap(
        const ParsedCommand& command
    );

    void handlePacketCapture(
        const ParsedCommand& command
    );

    void handlePacketInspect(
        const ParsedCommand& command
    );

    void handleNetworkMonitor(
        const ParsedCommand& command
    );

    void handleNetworkShow(
        const ParsedCommand& command
    );

    void handleNetworkClear(
        const ParsedCommand& command
    );

    void handleSecurityDetect(
        const ParsedCommand& command
    );

    void handleAIAnalyze(
        const ParsedCommand& command
    );

    void handleSessionInfo(
        const ParsedCommand& command
    );

    void handleHelp();

    void handleExit();
};