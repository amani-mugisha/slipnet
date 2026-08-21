#include "network/banner_grabber.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <cstring>

#include <netinet/in.h>

#include <sys/select.h>
#include <sys/socket.h>

#include <unistd.h>

BannerResult BannerGrabber::grab(
    const std::string& host,
    int port
) const
{
    BannerResult result;

    result.host = host;
    result.port = port;

    int socketFD =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (socketFD < 0)
    {
        return result;
    }

    sockaddr_in address{};

    address.sin_family = AF_INET;

    address.sin_port =
        htons(
            static_cast<std::uint16_t>(
                port
            )
        );

    if (
        inet_pton(
            AF_INET,
            host.c_str(),
            &address.sin_addr
        ) != 1
    )
    {
        close(socketFD);
        return result;
    }

    timeval timeout{};

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    setsockopt(
        socketFD,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout)
    );

    setsockopt(
        socketFD,
        SOL_SOCKET,
        SO_SNDTIMEO,
        &timeout,
        sizeof(timeout)
    );

    if (
        connect(
            socketFD,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        ) != 0
    )
    {
        close(socketFD);
        return result;
    }

    result.connected = true;

    /*
     * Protocol-aware request for HTTP.
     */
    if (
        port == 80 ||
        port == 8080 ||
        port == 8000 ||
        port == 8888
    )
    {
        const char request[] =
            "HEAD / HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n";

        send(
            socketFD,
            request,
            sizeof(request) - 1,
            0
        );

        result.protocol = "HTTP";
    }
    else if (port == 21)
    {
        result.protocol = "FTP";
    }
    else if (port == 22)
    {
        result.protocol = "SSH";
    }
    else if (port == 25)
    {
        result.protocol = "SMTP";
    }
    else
    {
        result.protocol = "TCP";
    }

    char buffer[4096]{};

    ssize_t received =
        recv(
            socketFD,
            buffer,
            sizeof(buffer) - 1,
            0
        );

    if (received > 0)
    {
        buffer[received] = '\0';

        result.banner =
            clean(
                std::string(
                    buffer,
                    static_cast<std::size_t>(
                        received
                    )
                )
            );
    }

    close(socketFD);

    return result;
}


std::string BannerGrabber::clean(
    const std::string& value
) const
{
    std::string result;

    for (char c : value)
    {
        if (c == '\r')
        {
            continue;
        }

        if (c == '\n')
        {
            result += " | ";
            continue;
        }

        if (
            static_cast<unsigned char>(c) < 32
        )
        {
            continue;
        }

        result += c;

        if (result.size() >= 512)
        {
            break;
        }
    }

    return result;
}