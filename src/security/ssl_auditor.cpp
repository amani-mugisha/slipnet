#include "security/ssl_auditor.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace
{
    std::string x509Name(
        X509_NAME* name
    )
    {
        if (!name)
        {
            return {};
        }

        char buffer[512] = {};

        X509_NAME_oneline(
            name,
            buffer,
            sizeof(buffer)
        );

        return buffer;
    }

    std::string asn1Time(
        const ASN1_TIME* time
    )
    {
        if (!time)
        {
            return {};
        }

        BIO* bio =
            BIO_new(
                BIO_s_mem()
            );

        if (!bio)
        {
            return {};
        }

        ASN1_TIME_print(
            bio,
            time
        );

        char* data = nullptr;

        const long length =
            BIO_get_mem_data(
                bio,
                &data
            );

        std::string result;

        if (data && length > 0)
        {
            result.assign(
                data,
                static_cast<std::size_t>(length)
            );
        }

        BIO_free(bio);

        return result;
    }

    int connectSocket(
        const std::string& host,
        int port
    )
    {
        struct addrinfo hints {};
        struct addrinfo* result = nullptr;

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        const std::string portString =
            std::to_string(port);

        if (
            getaddrinfo(
                host.c_str(),
                portString.c_str(),
                &hints,
                &result
            ) != 0
        )
        {
            return -1;
        }

        int socketFd = -1;

        for (
            auto* current = result;
            current != nullptr;
            current = current->ai_next
        )
        {
            socketFd =
                socket(
                    current->ai_family,
                    current->ai_socktype,
                    current->ai_protocol
                );

            if (socketFd < 0)
            {
                continue;
            }

            if (
                connect(
                    socketFd,
                    current->ai_addr,
                    current->ai_addrlen
                ) == 0
            )
            {
                break;
            }

            close(socketFd);

            socketFd = -1;
        }

        freeaddrinfo(result);

        return socketFd;
    }
}

bool SSLAuditor::parseTarget(
    const std::string& input,
    std::string& host,
    int& port
)
{
    if (input.empty())
    {
        return false;
    }

    host = input;
    port = 443;

    /*
     * IPv6:
     * [2001:db8::1]:443
     */
    if (input.front() == '[')
    {
        const auto close =
            input.find(']');

        if (close == std::string::npos)
        {
            return false;
        }

        host =
            input.substr(
                1,
                close - 1
            );

        if (
            close + 1 < input.size() &&
            input[close + 1] == ':'
        )
        {
            try
            {
                port =
                    std::stoi(
                        input.substr(close + 2)
                    );
            }
            catch (...)
            {
                return false;
            }
        }
    }
    else
    {
        const auto colon =
            input.rfind(':');

        /*
         * Treat :PORT as a port only when
         * there is exactly one colon.
         */
        if (
            colon != std::string::npos &&
            input.find(':') == colon
        )
        {
            try
            {
                port =
                    std::stoi(
                        input.substr(colon + 1)
                    );

                host =
                    input.substr(
                        0,
                        colon
                    );
            }
            catch (...)
            {
                return false;
            }
        }
    }

    return
        !host.empty() &&
        port >= 1 &&
        port <= 65535;
}

void SSLAuditor::addFindings(
    SSLAuditResult& result
)
{
    if (!result.certificateValid)
    {
        result.findings.push_back(
            {
                TLSSeverity::HIGH,
                "SLP-TLS-CERT-INVALID",
                "Certificate validation failed",
                "The presented certificate could not be "
                "validated successfully.",
                "Install a valid certificate chain and "
                "correct the certificate configuration."
            }
        );
    }

    if (!result.hostnameMatch)
    {
        result.findings.push_back(
            {
                TLSSeverity::HIGH,
                "SLP-TLS-HOSTNAME-MISMATCH",
                "Certificate hostname mismatch",
                "The certificate identity does not match "
                "the requested hostname.",
                "Install a certificate containing the correct "
                "DNS name in its SAN entries."
            }
        );
    }

    if (
        result.daysRemaining >= 0 &&
        result.daysRemaining <= 30
    )
    {
        result.findings.push_back(
            {
                TLSSeverity::MEDIUM,
                "SLP-TLS-EXPIRING",
                "Certificate expires soon",
                "The certificate has 30 or fewer days remaining.",
                "Renew the certificate before expiration."
            }
        );
    }

    if (
        result.protocol == "TLSv1" ||
        result.protocol == "TLSv1.1"
    )
    {
        result.findings.push_back(
            {
                TLSSeverity::HIGH,
                "SLP-TLS-LEGACY-PROTOCOL",
                "Legacy TLS protocol negotiated",
                "The endpoint negotiated an obsolete TLS protocol.",
                "Disable legacy TLS and require TLS 1.2 or newer."
            }
        );
    }

    if (
        result.protocol == "TLSv1.2" ||
        result.protocol == "TLSv1.3"
    )
    {
        /*
         * Informational finding so the report clearly
         * explains that modern TLS was observed.
         */
        result.findings.push_back(
            {
                TLSSeverity::INFO,
                "SLP-TLS-MODERN",
                "Modern TLS protocol observed",
                "The endpoint negotiated a currently preferred "
                "TLS protocol generation.",
                "Continue monitoring TLS configuration."
            }
        );
    }
}

SSLAuditResult
SSLAuditor::audit(
    const std::string& target
) const
{
    SSLAuditResult result;

    if (
        !parseTarget(
            target,
            result.host,
            result.port
        )
    )
    {
        result.error =
            "Invalid target. Expected HOST or HOST:PORT.";

        return result;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx =
        SSL_CTX_new(
            TLS_client_method()
        );

    if (!ctx)
    {
        result.error =
            "Unable to initialize OpenSSL.";

        return result;
    }

    /*
     * We verify the peer certificate.
     */
    SSL_CTX_set_verify(
        ctx,
        SSL_VERIFY_PEER,
        nullptr
    );

    SSL_CTX_set_default_verify_paths(ctx);

    int socketFd =
        connectSocket(
            result.host,
            result.port
        );

    if (socketFd < 0)
    {
        result.error =
            "Unable to connect to TLS endpoint.";

        SSL_CTX_free(ctx);

        return result;
    }

    SSL* ssl =
        SSL_new(ctx);

    if (!ssl)
    {
        result.error =
            "Unable to create TLS session.";

        close(socketFd);
        SSL_CTX_free(ctx);

        return result;
    }

    SSL_set_fd(
        ssl,
        socketFd
    );

    /*
     * SNI is essential for modern virtual-hosted TLS.
     */
    SSL_set_tlsext_host_name(
        ssl,
        result.host.c_str()
    );

    if (
        SSL_connect(ssl) != 1
    )
    {
        result.error =
            "TLS handshake failed.";

        SSL_free(ssl);
        close(socketFd);
        SSL_CTX_free(ctx);

        return result;
    }

    result.success = true;

    const char* version =
        SSL_get_version(ssl);

    if (version)
    {
        result.protocol = version;
    }

    const char* cipher =
        SSL_get_cipher_name(ssl);

    if (cipher)
    {
        result.cipher = cipher;
    }

    X509* certificate =
        SSL_get_peer_certificate(ssl);

    if (certificate)
    {
        result.subject =
            x509Name(
                X509_get_subject_name(
                    certificate
                )
            );

        result.issuer =
            x509Name(
                X509_get_issuer_name(
                    certificate
                )
            );

        result.validFrom =
            asn1Time(
                X509_get0_notBefore(
                    certificate
                )
            );

        result.validUntil =
            asn1Time(
                X509_get0_notAfter(
                    certificate
                )
            );

        /*
         * OpenSSL performs certificate chain verification.
         */
        result.certificateValid =
            SSL_get_verify_result(ssl) ==
            X509_V_OK;

        result.hostnameMatch =
            X509_check_host(
                certificate,
                result.host.c_str(),
                result.host.size(),
                0,
                nullptr
            ) == 1;

        X509_free(certificate);
    }

    addFindings(result);

    SSL_shutdown(ssl);
    SSL_free(ssl);

    close(socketFd);
    SSL_CTX_free(ctx);

    return result;
}