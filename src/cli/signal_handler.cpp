#include "cli/signal_handler.hpp"

#include <csignal>

std::atomic<bool>
SignalHandler::stopRequested(false);


void SignalHandler::handleSignal(
    int signal
)
{
    if (signal == SIGINT)
    {
        stopRequested.store(
            true,
            std::memory_order_relaxed
        );
    }
}


void SignalHandler::initialize()
{
    std::signal(
        SIGINT,
        SignalHandler::handleSignal
    );
}


bool SignalHandler::isStopRequested()
{
    return stopRequested.load(
        std::memory_order_relaxed
    );
}


void SignalHandler::requestStop()
{
    stopRequested.store(
        true,
        std::memory_order_relaxed
    );
}


void SignalHandler::clearStop()
{
    stopRequested.store(
        false,
        std::memory_order_relaxed
    );
}