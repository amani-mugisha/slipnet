#include "cli/terminal.hpp"

#include <iostream>

#include <string>

#include "cli/command_parser.hpp"

#include "core/engine_context.hpp"

#include "core/network_state.hpp"

#include "cli/command_handler.hpp"

#include "cli/signal_handler.hpp"


void Terminal::run()
{
    std::cout << R"(

========================================
              SLIPNET
       NETWORK INTELLIGENCE ENGINE
========================================

Type 'help' for available commands.
Press Ctrl+C to stop the current operation.
Type 'fire' to exit SlipNet.

)";


    CommandParser parser;

    EngineContext context;

    CommandHandler handler(context);    

    std::string input;


    while (true)
    {
        /*
            Reset the stop flag before
            waiting for a new command.
        */

        SignalHandler::clearStop();


        std::cout
            << "slipnet> "
            << std::flush;


        if (
            !std::getline(
                std::cin,
                input
            )
        )
        {
            break;
        }


        /*
            If Ctrl+C was pressed while
            reading input, exit cleanly.
        */

        if (
            SignalHandler::isStopRequested()
        )
        {
            std::cout
                << "\n"
                << "[!] SlipNet interrupted.\n";

            break;
        }


        if (input.empty())
        {
            continue;
        }


        ParsedCommand command =
            parser.parse(input);


        bool running =
            handler.execute(command);


        if (!running)
        {
            break;
        }
    }


    std::cout
        << "\nSlipNet terminated.\n";
}