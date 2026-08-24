#include "platform/sockets.hpp"

#ifndef _WIN32

#include <cerrno>
#include <unistd.h>

namespace slipnet::platform {

bool initializeSockets()
{
    return true;
}

void shutdownSockets()
{
    // Nothing required for POSIX sockets.
}

bool isValidSocket(SocketHandle socket)
{
    return socket >= 0;
}

void closeSocket(SocketHandle socket)
{
    if (isValidSocket(socket)) {
        ::close(socket);
    }
}

int getLastSocketError()
{
    return errno;
}

} // namespace slipnet::platform

#endif