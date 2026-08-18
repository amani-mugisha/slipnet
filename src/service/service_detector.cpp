#include "service/service_detector.hpp"

#include <arpa/inet.h>

#include <chrono>

#include <cstring>

#include <netinet/in.h>

#include <sys/socket.h>

#include <unistd.h>


namespace
{

constexpr int CONNECTION_TIMEOUT_SECONDS = 2;

constexpr int BUFFER_SIZE = 4096;


bool connectToHost(
    int socketFD,
    const std::string& host,
    int port
)
{
    sockaddr_in address{};

    address.sin_family = AF_INET;

    address.sin_port =
        htons(
            static_cast<uint16_t>(port)
        );


    if (
        inet_pton(
            AF_INET,
            host.c_str(),
            &address.sin_addr
        ) != 1
    )
    {
        return false;
    }


    timeval timeout{};

    timeout.tv_sec =
        CONNECTION_TIMEOUT_SECONDS;

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


    return
        connect(
            socketFD,
            reinterpret_cast<sockaddr*>(
                &address
            ),
            sizeof(address)
        ) == 0;
}

}


/*
    Attempt to obtain a response/banner
    from a TCP service.
*/
std::string ServiceDetector::probe(
    const std::string& host,
    int port
) const
{
    int socketFD =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );


    if (socketFD < 0)
    {
        return {};
    }


    if (
        !connectToHost(
            socketFD,
            host,
            port
        )
    )
    {
        close(socketFD);

        return {};
    }


    /*
        HTTP requires an application-level
        request before the server normally
        sends its response.
    */

    if (
        port == 80 ||
        port == 8080 ||
        port == 8000 ||
        port == 8888
    )
    {
        const char* request =
            "HEAD / HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n";


        send(
            socketFD,
            request,
            std::strlen(request),
            0
        );
    }


    char buffer[BUFFER_SIZE];

    std::memset(
        buffer,
        0,
        sizeof(buffer)
    );


    ssize_t received =
        recv(
            socketFD,
            buffer,
            sizeof(buffer) - 1,
            0
        );


    close(socketFD);


    if (received <= 0)
    {
        return {};
    }


    buffer[received] = '\0';


    return std::string(
        buffer,
        static_cast<std::size_t>(
            received
        )
    );
}


/*
    Identify a service using its response
    and a small amount of protocol knowledge.
*/
Service ServiceDetector::identify(
    int port,
    const std::string& response
) const
{
    Service service{};

    service.port = port;

    service.protocol = "TCP";

    service.name = "Unknown";

    service.version = "";

    service.banner = response;

    service.detected = false;


    /*
        SSH
    */

    if (
        response.rfind(
            "SSH-",
            0
        ) == 0
    )
    {
        service.name = "SSH";

        service.detected = true;

        service.version = response;

        return service;
    }


    /*
        FTP
    */

    if (
        response.rfind(
            "220",
            0
        ) == 0
    )
    {
        if (
            port == 21 ||
            response.find("FTP")
                != std::string::npos
        )
        {
            service.name = "FTP";

            service.detected = true;

            return service;
        }
    }


    /*
        HTTP
    */

    if (
        response.find("HTTP/")
            != std::string::npos
    )
    {
        service.name = "HTTP";

        service.detected = true;


        /*
            Attempt to extract the
            Server header.
        */

        std::size_t position =
            response.find(
                "Server:"
            );


        if (
            position
            != std::string::npos
        )
        {
            std::size_t start =
                position + 7;


            std::size_t end =
                response.find(
                    '\n',
                    start
                );


            if (
                end
                == std::string::npos
            )
            {
                end =
                    response.size();
            }


            service.version =
                response.substr(
                    start,
                    end - start
                );
        }


        return service;
    }


    /*
        MySQL commonly uses port 3306.
    */

    if (port == 3306)
    {
        service.name = "MySQL";

        service.detected = true;

        return service;
    }


    /*
        PostgreSQL commonly uses 5432.
    */

    if (port == 5432)
    {
        service.name = "PostgreSQL";

        service.detected = true;

        return service;
    }


    /*
        Redis commonly uses 6379.
    */

    if (port == 6379)
    {
        service.name = "Redis";

        service.detected = true;

        return service;
    }


    /*
        Known port fallback.
    */

    switch (port)
    {
        case 22:
            service.name = "SSH";
            service.detected = true;
            break;

        case 21:
            service.name = "FTP";
            service.detected = true;
            break;

        case 25:
            service.name = "SMTP";
            service.detected = true;
            break;

        case 53:
            service.name = "DNS";
            service.detected = true;
            break;

        case 80:
            service.name = "HTTP";
            service.detected = true;
            break;

        case 443:
            service.name = "HTTPS";
            service.detected = true;
            break;

        case 110:
            service.name = "POP3";
            service.detected = true;
            break;

        case 143:
            service.name = "IMAP";
            service.detected = true;
            break;

        default:
            break;
    }


    return service;
}


/*
    Detect one service.
*/
Service ServiceDetector::detect(
    const std::string& host,
    int port
) const
{
    std::string response =
        probe(
            host,
            port
        );


    return identify(
        port,
        response
    );
}


/*
    Detect several services.
*/
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
                service
            );
        }
    }


    return results;
}