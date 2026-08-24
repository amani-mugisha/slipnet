#pragma once

#include <string>

namespace slipnet::platform
{

struct TcpConnection
{
    int handle{-1};
    bool valid{false};
};

TcpConnection tcpConnect(
    const std::string& host,
    int port,
    int timeoutMs = 2000
);

bool tcpSend(
    TcpConnection& connection,
    const std::string& data
);

std::string tcpReceive(
    TcpConnection& connection,
    int maxBytes = 4096
);

void tcpClose(
    TcpConnection& connection
);

} // namespace slipnet::platform