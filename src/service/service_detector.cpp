#include "service/service_detector.hpp"

#include "platform/tcp.hpp"

#include <algorithm>
#include <cctype>
#include <string>


namespace
{

constexpr int DEFAULT_TIMEOUT_MS = 2000;
constexpr int BUFFER_SIZE = 4096;


std::string trim(
    std::string value
)
{
    while (
        !value.empty() &&
        std::isspace(
            static_cast<unsigned char>(
                value.front()
            )
        )
    )
    {
        value.erase(
            value.begin()
        );
    }

    while (
        !value.empty() &&
        std::isspace(
            static_cast<unsigned char>(
                value.back()
            )
        )
    )
    {
        value.pop_back();
    }

    return value;
}


bool startsWith(
    const std::string& value,
    const std::string& prefix
)
{
    return
        value.rfind(prefix, 0)
        == 0;
}


std::string extractHeader(
    const std::string& response,
    const std::string& header
)
{
    std::size_t position =
        response.find(header);

    if (
        position == std::string::npos
    )
    {
        return {};
    }

    std::size_t start =
        position + header.size();

    std::size_t end =
        response.find(
            '\n',
            start
        );

    if (
        end == std::string::npos
    )
    {
        end =
            response.size();
    }

    return trim(
        response.substr(
            start,
            end - start
        )
    );
}

} // namespace


std::string ServiceDetector::probe(
    const std::string& host,
    int port
) const
{
    auto connection =
        slipnet::platform::tcpConnect(
            host,
            port,
            DEFAULT_TIMEOUT_MS
        );

    if (!connection.valid)
    {
        return {};
    }

    /*
     * HTTP services normally require
     * an application-level request.
     */
    if (
        port == 80 ||
        port == 443 ||
        port == 8000 ||
        port == 8080 ||
        port == 8443 ||
        port == 8888
    )
    {
        const std::string request =
            "HEAD / HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n";

        slipnet::platform::tcpSend(
            connection,
            request
        );
    }

    std::string response =
        slipnet::platform::tcpReceive(
            connection,
            BUFFER_SIZE
        );

    slipnet::platform::tcpClose(
        connection
    );

    return response;
}


Service ServiceDetector::identify(
    int port,
    const std::string& response
) const
{
    Service service{};

    service.port = port;
    service.protocol = "TCP";
    service.name = "Unknown";
    service.version = {};
    service.banner = response;
    service.detected = false;


    /*
     * SSH
     */
    if (
        startsWith(
            response,
            "SSH-"
        )
    )
    {
        service.name = "SSH";
        service.detected = true;

        std::size_t newline =
            response.find('\n');

        service.version =
            trim(
                response.substr(
                    0,
                    newline
                )
            );

        return service;
    }


    /*
     * FTP
     */
    if (
        port == 21 &&
        (
            startsWith(
                response,
                "220"
            ) ||
            response.find("FTP")
                != std::string::npos
        )
    )
    {
        service.name = "FTP";
        service.detected = true;

        return service;
    }


    /*
     * HTTP
     */
    if (
        response.find("HTTP/")
        != std::string::npos
    )
    {
        service.name = "HTTP";
        service.detected = true;

        service.version =
            extractHeader(
                response,
                "Server:"
            );

        return service;
    }


    /*
     * SMTP
     */
    if (
        port == 25 &&
        startsWith(
            response,
            "220"
        )
    )
    {
        service.name = "SMTP";
        service.detected = true;

        return service;
    }


    /*
     * MySQL
     *
     * MySQL normally sends a binary
     * handshake packet immediately
     * after connection.
     */
    if (port == 3306)
    {
        if (!response.empty())
        {
            service.name = "MySQL";
            service.detected = true;
        }

        return service;
    }


    /*
     * PostgreSQL
     *
     * PostgreSQL does not normally send
     * a banner immediately, so port
     * knowledge is used as a fallback.
     */
    if (port == 5432)
    {
        service.name = "PostgreSQL";
        service.detected = true;

        return service;
    }


    /*
     * Redis
     */
    if (
        port == 6379 &&
        (
            response.find("+") == 0 ||
            response.find("-") == 0
        )
    )
    {
        service.name = "Redis";
        service.detected = true;

        return service;
    }


    /*
     * Known-service fallback.
     *
     * Port numbers alone are NOT proof
     * of the actual service. We therefore
     * mark these as detected only when
     * the probe gave us some evidence,
     * except for protocols where the
     * handshake is commonly silent.
     */
    switch (port)
    {
        case 22:
            if (!response.empty())
            {
                service.name = "SSH";
                service.detected = true;
            }
            break;

        case 53:
            service.name = "DNS";
            service.detected = true;
            break;

        case 110:
            if (
                startsWith(
                    response,
                    "+OK"
                )
            )
            {
                service.name = "POP3";
                service.detected = true;
            }
            break;

        case 143:
            if (
                response.find("* OK")
                != std::string::npos
            )
            {
                service.name = "IMAP";
                service.detected = true;
            }
            break;

        case 443:
            /*
             * A TCP connection on 443 proves
             * the port is reachable, but without
             * TLS negotiation we should not claim
             * the application is HTTPS.
             */
            break;

        default:
            break;
    }

    return service;
}


Service ServiceDetector::detect(
    const std::string& host,
    int port
) const
{
    if (
        port < 1 ||
        port > 65535
    )
    {
        return {};
    }

    const std::string response =
        probe(
            host,
            port
        );

    return identify(
        port,
        response
    );
}


std::vector<Service>
ServiceDetector::detect(
    const std::string& host,
    const std::vector<int>& ports
) const
{
    std::vector<Service> results;

    for (
        int port :
        ports
    )
    {
        Service service =
            detect(
                host,
                port
            );

        if (service.detected)
        {
            results.push_back(
                std::move(service)
            );
        }
    }

    return results;
}