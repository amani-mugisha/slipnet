#pragma once

#include <atomic>

class SignalHandler
{
public:

    static void initialize();

    static bool isStopRequested();

    static void requestStop();

    static void clearStop();

private:

    static void handleSignal(int signal);

    static std::atomic<bool> stopRequested;
};