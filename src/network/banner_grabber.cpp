#include "network/banner_grabber.hpp"
#include "platform/tcp.hpp"

#include <string>

BannerResult BannerGrabber::grab(
    const std::string& host,
    int port
) const
{
    BannerResult result;

    result.host = host;
    result.port = port;

    /*
     * --------------------------------------------------------
     * Determine protocol
     * --------------------------------------------------------
     */

    if (
        port == 80 ||
        port == 8080 ||
        port == 8000 ||
        port == 8888
    )
    {
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
    else if (
        port == 110 ||
        port == 995
    )
    {
        result.protocol = "POP3";
    }
    else if (
        port == 143 ||
        port == 993
    )
    {
        result.protocol = "IMAP";
    }
    else if (
        port == 53
    )
    {
        result.protocol = "DNS";
    }
    else if (
        port == 443 ||
        port == 8443
    )
    {
        result.protocol = "HTTPS";
    }
    else
    {
        result.protocol = "TCP";
    }


    /*
     * --------------------------------------------------------
     * Establish TCP connection
     * --------------------------------------------------------
     */

    auto connection =
        slipnet::platform::tcpConnect(
            host,
            port,
            2000
        );

    if (!connection.valid)
    {
        return result;
    }

    result.connected = true;


    /*
     * --------------------------------------------------------
     * Protocol-aware requests
     * --------------------------------------------------------
     *
     * Some services send a banner immediately.
     *
     * HTTP does not normally do this, so send a lightweight
     * HEAD request first.
     */

    if (
        result.protocol == "HTTP"
    )
    {
        const std::string request =
            "HEAD / HTTP/1.0\r\n"
            "Host: " + host + "\r\n"
            "Connection: close\r\n"
            "\r\n";

        slipnet::platform::tcpSend(
            connection,
            request
        );
    }


    /*
     * --------------------------------------------------------
     * Receive banner
     * --------------------------------------------------------
     */

    const std::string banner =
        slipnet::platform::tcpReceive(
            connection,
            4096
        );

    if (!banner.empty())
    {
        result.banner =
            clean(banner);
    }


    /*
     * --------------------------------------------------------
     * Close connection
     * --------------------------------------------------------
     */

    slipnet::platform::tcpClose(
        connection
    );

    return result;
}


std::string BannerGrabber::clean(
    const std::string& value
) const
{
    std::string result;

    result.reserve(
        value.size()
    );

    for (char c : value)
    {
        /*
         * Remove carriage returns.
         */
        if (c == '\r')
        {
            continue;
        }

        /*
         * Convert line breaks into readable separators.
         */
        if (c == '\n')
        {
            if (
                !result.empty() &&
                result.back() != ' '
            )
            {
                result += " | ";
            }

            continue;
        }

        /*
         * Ignore control characters.
         */
        if (
            static_cast<unsigned char>(c) < 32
        )
        {
            continue;
        }

        result += c;

        /*
         * Keep CLI output bounded.
         */
        if (result.size() >= 512)
        {
            break;
        }
    }

    return result;
}