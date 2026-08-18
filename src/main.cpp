#include "cli/terminal.hpp"

#include "cli/signal_handler.hpp"


int main()
{
    SignalHandler::initialize();

    Terminal terminal;

    terminal.run();

    return 0;
}